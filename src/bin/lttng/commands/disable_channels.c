/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <common/mi-lttng.h>

#include "../command.h"

static char *opt_channels;
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
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

static int mi_partial_channel_print(char *channel_name, unsigned int enabled,
		int success)
{
	int ret;

	assert(writer);
	assert(channel_name);

	/* Open channel element */
	ret = mi_lttng_writer_open_element(writer, config_element_channel);
	if (ret) {
		goto end;
	}

	/* Name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name,
			channel_name);
	if (ret) {
		goto end;
	}

	/* Enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled,
			enabled);
	if (ret) {
		goto end;
	}

	/* Success ? */
	ret = mi_lttng_writer_write_element_bool(writer,
			mi_lttng_element_success, success);
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
static int disable_channels(char *session_name)
{
	int ret = CMD_SUCCESS, warn = 0, success;

	/* Normal case for disable channed is enabled = 0 */
	unsigned int enabled = 0;
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
		assert(0);
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
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
	channel_name = strtok(opt_channels, ",");
	while (channel_name != NULL) {
		DBG("Disabling channel %s", channel_name);

		ret = lttng_disable_channel(handle, channel_name);
		if (ret < 0) {
			ERR("Channel %s: %s (session %s)", channel_name,
					lttng_strerror(ret), session_name);
			warn = 1;

			/*
			 * Mi:
			 * We assume that if an error occurred the channel is still active.
			 * This might not be the case but is a good assumption.
			 * The client should look at the stderr stream
			 * for more informations.
			 */
			enabled = 1;
			success = 0;

		} else {
			MSG("%s channel %s disabled for session %s",
					get_domain_str(dom.type), channel_name, session_name);
			enabled = 0;
			success = 1;
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
		channel_name = strtok(NULL, ",");
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
	char *session_name = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
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

	ret = print_missing_or_multiple_domains(opt_kernel + opt_userspace);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	opt_channels = (char*) poptGetArg(pc);
	if (opt_channels == NULL) {
		ERR("Missing channel name(s).\n");
		ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
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
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	command_ret = disable_channels(session_name);
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
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_success, success);
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

	/* Overwrite ret if an error occurred in disable_channels */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
