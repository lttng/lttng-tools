/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>

#include <lttng/domain-internal.hpp>

#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int opt_kernel;
static char *opt_session_name;
static int opt_userspace;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-disable-channel.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;
static struct mi_writer *writer;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "session", 's', POPT_ARG_STRING, &opt_session_name, 0, nullptr, nullptr },
	{ "kernel", 'k', POPT_ARG_VAL, &opt_kernel, 1, nullptr, nullptr },
	{ "userspace", 'u', POPT_ARG_NONE, nullptr, OPT_USERSPACE, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

static int mi_partial_channel_print(char *channel_name, unsigned int enabled, int success)
{
	int ret;

	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(channel_name);

	/* Open channel element */
	ret = mi_lttng_writer_open_element(writer, config_element_channel);
	if (ret) {
		goto end;
	}

	/* Name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, channel_name);
	if (ret) {
		goto end;
	}

	/* Enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled, enabled);
	if (ret) {
		goto end;
	}

	/* Success ? */
	ret = mi_lttng_writer_write_element_bool(writer, mi_lttng_element_success, success);
	if (ret) {
		goto end;
	}

	/* Closing channel element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

/*
 * Disabling channel using the lttng API.
 */
static int disable_channels(char *session_name, char *channel_list)
{
	int ret = CMD_SUCCESS;
	/* Normal case for disable channed is enabled = false */
	bool warn = false, success, enabled = false;
	char *channel_name;
	struct lttng_domain dom;

	memset(&dom, 0, sizeof(dom));

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		/* Checked by the caller. */
		abort();
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == nullptr) {
		ret = -1;
		goto error;
	}

	/* Prepare MI */
	if (lttng_opt_mi) {
		/* open a channels element */
		ret = mi_lttng_writer_open_element(writer, config_element_channels);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	/* Strip channel list */
	channel_name = strtok(channel_list, ",");
	while (channel_name != nullptr) {
		DBG("Disabling channel %s", channel_name);

		ret = lttng_disable_channel(handle, channel_name);
		if (ret < 0) {
			ERR("Channel %s: %s (session %s)",
			    channel_name,
			    lttng_strerror(ret),
			    session_name);
			warn = true;

			/*
			 * Mi:
			 * We assume that if an error occurred the channel is still active.
			 * This might not be the case but is a good assumption.
			 * The client should look at the stderr stream
			 * for more informations.
			 */
			enabled = true;
			success = false;

		} else {
			MSG("%s channel %s disabled for session %s",
			    lttng_domain_type_str(dom.type),
			    channel_name,
			    session_name);
			enabled = false;
			success = true;
		}

		/* Print the channel */
		if (lttng_opt_mi) {
			ret = mi_partial_channel_print(channel_name, enabled, success);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}

		/* Next channel */
		channel_name = strtok(nullptr, ",");
	}

	ret = CMD_SUCCESS;

	/* Close Mi */
	if (lttng_opt_mi) {
		/* Close channels element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

error:
	/* Bypass the warning if a more important error happened */
	if (!ret && warn) {
		ret = CMD_WARNING;
	}

	lttng_destroy_handle(handle);

	return ret;
}

/*
 *  cmd_disable_channels
 *
 *  Disable channel to trace session
 */
int cmd_disable_channels(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;
	char *session_name = nullptr;
	char *channel_list = nullptr;
	const char *arg_channel_list = nullptr;
	const char *leftover = nullptr;

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = print_missing_or_multiple_domains(opt_kernel + opt_userspace, false);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	arg_channel_list = poptGetArg(pc);
	if (arg_channel_list == nullptr) {
		ERR("Missing channel name(s).");
		ret = CMD_ERROR;
		goto end;
	}

	channel_list = strdup(arg_channel_list);
	if (channel_list == nullptr) {
		PERROR("Failed to copy channel name");
		ret = CMD_ERROR;
		goto end;
	}

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == nullptr) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
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
						   mi_lttng_element_command_disable_channel);
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
	}

	command_ret = disable_channels(session_name, channel_list);
	if (command_ret) {
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer, mi_lttng_element_success, success);
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
		ret = ret ? ret : LTTNG_ERR_MI_IO_FAIL;
	}

	if (!opt_session_name && session_name) {
		free(session_name);
	}

	free(channel_list);

	/* Overwrite ret if an error occurred in disable_channels */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
