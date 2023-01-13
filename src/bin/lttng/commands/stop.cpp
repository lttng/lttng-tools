/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int opt_no_wait;
static struct mi_writer *writer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-stop.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0 },
	{ "list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL },
	{ "no-wait", 'n', POPT_ARG_VAL, &opt_no_wait, 1, 0, 0 },
	{ 0, 0, 0, 0, 0, 0, 0 }
};

/*
 * Mi print of partial session
 */
static int mi_print_session(char *session_name, int enabled)
{
	int ret;
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(session_name);

	/* Open session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	/* Print session name element */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, session_name);
	if (ret) {
		goto end;
	}

	/* Is enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled, enabled);
	if (ret) {
		goto end;
	}

	/* Close session element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

/*
 * Start tracing for all trace of the session.
 */
static int stop_tracing(const char *arg_session_name)
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

	ret = lttng_stop_tracing_no_wait(session_name);
	if (ret < 0) {
		switch (-ret) {
		case LTTNG_ERR_TRACE_ALREADY_STOPPED:
			WARN("Tracing already stopped for session %s", session_name);
			break;
		default:
			ERR("%s", lttng_strerror(ret));
			break;
		}
		goto free_name;
	}

	if (!opt_no_wait) {
		_MSG("Waiting for data availability");
		fflush(stdout);
		do {
			ret = lttng_data_pending(session_name);
			if (ret < 0) {
				/* Return the data available call error. */
				goto free_name;
			}

			/*
			 * Data sleep time before retrying (in usec). Don't sleep if the call
			 * returned value indicates availability.
			 */
			if (ret) {
				usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME_US);
				_MSG(".");
				fflush(stdout);
			}
		} while (ret != 0);
		MSG("");
	}

	ret = CMD_SUCCESS;

	print_session_stats(session_name);
	MSG("Tracing stopped for session %s", session_name);
	if (lttng_opt_mi) {
		ret = mi_print_session(session_name, 0);
		if (ret) {
			goto free_name;
		}
	}

free_name:
	free(session_name);

error:
	return ret;
}

/*
 *  cmd_stop
 *
 *  The 'stop <options>' first level command
 */
int cmd_stop(int argc, const char **argv)
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

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer, mi_lttng_element_command_stop);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/*
		 * Open sessions element
		 * For validation
		 */
		ret = mi_lttng_writer_open_element(writer, config_element_sessions);
		if (ret) {
			ret = CMD_ERROR;
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

	command_ret = stop_tracing(arg_session_name);
	if (command_ret) {
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close sessions and  output element */
		ret = mi_lttng_close_multi_element(writer, 2);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, success);
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

	/* Overwrite ret if an error occurred in stop_tracing() */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
