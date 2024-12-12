/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <fcntl.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/mi-lttng.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/utils.h>

#include "../command.h"

static struct mi_writer *writer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-start.1.h>
		;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

static int mi_print_session(char *session_name, int enabled)
{
	int ret;

	/* Open session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	/* Print session name element */
	ret = mi_lttng_writer_write_element_string(
			writer, config_element_name, session_name);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_bool(
			writer, config_element_enabled, enabled);
	if (ret) {
		goto end;
	}

	/* Close session element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

static enum lttng_error_code estimate_session_minimum_shm_size(
		const struct lttng_session *session,
		unsigned long *estimated_size)
{
	unsigned int ncpus = 0;
	unsigned long est_min_size = 0;
	struct lttng_handle *handle = NULL;
	struct lttng_domain *domains = NULL;
	struct lttng_channel *channels = NULL;
	int channel_count = 0, domain_count = 0;
	enum lttng_error_code ret_code = LTTNG_ERR_INVALID;

	if (utils_get_cpu_count(&ncpus) != LTTNG_OK) {
		ret_code = LTTNG_ERR_EPERM;
		return ret_code;
	}

	domain_count = lttng_list_domains(session->name, &domains);
	if (domain_count < 0) {
		ERR("Failed to list domains for session '%s'", session->name);
		return ret_code;
	}

	for (int domain_idx = 0; domain_idx < domain_count; domain_idx++) {
		switch (domains[domain_idx].type) {
		case LTTNG_DOMAIN_UST:
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
			break;
		default:
			DBG("Domain %d not supported for shm estimation",
					domains[domain_idx].type);
			continue;
		}

		handle = lttng_create_handle(session->name, &domains[domain_idx]);
		if (!handle) {
			ERR("Failed to create lttng handle for session '%s', domain %d",
					session->name, domains[domain_idx].type);
			continue;
		}

		channel_count = lttng_list_channels(handle, &channels);
		if (channel_count < 0) {
			ERR("Failed to list channels for session '%s', domain %d",
					session->name, domains[domain_idx].type);
			goto error_free_handle;
		}

		for (int channel_idx = 0; channel_idx < channel_count;
				channel_idx++) {
			/*
			 * This assumes per-uid or per-pid buffers with a
			 * minimum of one uid or pid.
			 */
			est_min_size += ((ncpus + session->snapshot_mode) *
					channels[channel_idx].attr.num_subbuf *
					channels[channel_idx].attr.subbuf_size);
		}

error_free_handle:
		free(handle);
		handle = NULL;
		free(channels);
		channels = NULL;
		channel_count = 0;
	}

	if (estimated_size != NULL) {
		ret_code = LTTNG_OK;
		*estimated_size = est_min_size;
	}

	free(domains);
	return ret_code;
}

static void warn_on_small_client_shm(const char *session_name)
{
	int fd = -1, session_count = 0;
	struct statvfs statbuf;
	unsigned long estimated_size = 0, memfd_device_size = 0;
	struct lttng_session *sessions = NULL, *this_session = NULL;
	const char *CLIENT_SHM_TEST_PATH = "/lttng-client-fake";
	char *parent = NULL;

	session_count = lttng_list_sessions(&sessions);
	if (session_count <= 0) {
		return;
	}

	for (int i = 0; i < session_count; i++) {
		if (strcmp(session_name, sessions[i].name) == 0) {
			this_session = &sessions[i];
			break;
		}
	}

	if (this_session == NULL) {
		goto error_free_sessions;
	}

	/*
	 * To avoid making API additions during the stable release cycle, this
	 * check will assume that the shared memory path for a given session
	 * has not been overridden.
	 */
	fd = shm_open(CLIENT_SHM_TEST_PATH, O_RDWR | O_CREAT, 0700);
	if (fd < 0) {
		WARN("Failed to open shared memory at path '%s' errno %d",
				CLIENT_SHM_TEST_PATH, errno);
		goto error_free_parent;
	}

	if (fstatvfs(fd, &statbuf) != 0) {
		WARN("Failed to get the capacity of the filesystem at the default location use by shm_open error %d",
				errno);
		goto error_close_fd;
	}

	memfd_device_size = statbuf.f_frsize * statbuf.f_blocks;
	DBG("memfd device id `%lu` has size %lu bytes", statbuf.f_fsid,
			memfd_device_size);
	if (estimate_session_minimum_shm_size(this_session, &estimated_size) !=
			LTTNG_OK) {
		WARN("Failed to estimate minimum shm size for session '%s'",
				this_session->name);
		goto error_close_fd;
	}

	DBG("Estimated min shm for session '%s': %lu", this_session->name,
			estimated_size);
	if (estimated_size >= memfd_device_size) {
		WARN("The estimated minimum shared memory size for all non-kernel channels of session '%s' is greater than the total shared memory allocated to the default shared memory location (%luMiB >= %luMiB). Tracing for this session may not record events due to allocation failures.",
				session_name, estimated_size / 1024 / 1024,
				memfd_device_size / 1024 / 1024);
	}

error_close_fd:
	if (fd >= 0) {
		close(fd);
		shm_unlink(CLIENT_SHM_TEST_PATH);
	}

error_free_parent:
	free(parent);
error_free_sessions:
	free(sessions);
}

/*
 *  start_tracing
 *
 *  Start tracing for all trace of the session.
 */
static int start_tracing(const char *arg_session_name)
{
	int ret;
	char *session_name;

	if (arg_session_name == NULL) {
		session_name = get_session_name();
	} else {
		session_name = strdup(arg_session_name);
		if (session_name == NULL) {
			PERROR("Failed to copy session name");
		}
	}

	if (session_name == NULL) {
		ret = CMD_ERROR;
		goto error;
	}

	DBG("Starting tracing for session %s", session_name);
	warn_on_small_client_shm(session_name);
	ret = lttng_start_tracing(session_name);
	if (ret < 0) {
		switch (-ret) {
		case LTTNG_ERR_TRACE_ALREADY_STARTED:
			WARN("Tracing already started for session %s",
					session_name);
			break;
		default:
			ERR("%s", lttng_strerror(ret));
			break;
		}
		goto free_name;
	}

	ret = CMD_SUCCESS;

	MSG("Tracing started for session %s", session_name);
	if (lttng_opt_mi) {
		ret = mi_print_session(session_name, 1);
		if (ret) {
			ret = CMD_ERROR;
			goto free_name;
		}
	}

free_name:
	free(session_name);
error:
	return ret;
}

/*
 *  cmd_start
 *
 *  The 'start <options>' first level command
 */
int cmd_start(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;
	const char *arg_session_name = NULL;
	const char *leftover = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	arg_session_name = poptGetArg(pc);

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_start);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/*
		 * Open sessions element
		 * For validation purpose
		 */
		ret = mi_lttng_writer_open_element(writer,
			config_element_sessions);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	command_ret = start_tracing(arg_session_name);
	if (command_ret) {
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  sessions and output element */
		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

	/* Overwrite ret if an error occurred with start_tracing */
	ret = command_ret ? command_ret : ret;
	poptFreeContext(pc);
	return ret;
}
