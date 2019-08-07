/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
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
#include <inttypes.h>
#include <ctype.h>
#include <assert.h>

#include <common/sessiond-comm/sessiond-comm.h>
#include <common/mi-lttng.h>

#include "../command.h"
#include <lttng/rotation.h>
#include <lttng/location.h>

static char *opt_session_name;
static int opt_no_wait;
static struct mi_writer *writer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-rotate.1.h>
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
	{"no-wait",   'n', POPT_ARG_VAL, &opt_no_wait, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

static int rotate_tracing(char *session_name)
{
	int ret;
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	struct lttng_rotation_handle *handle = NULL;
	enum lttng_rotation_status rotation_status;
	enum lttng_rotation_state rotation_state = LTTNG_ROTATION_STATE_ONGOING;
	const struct lttng_trace_archive_location *location = NULL;
	bool print_location = true;

	DBG("Rotating the output files of session %s", session_name);

	ret = lttng_rotate_session(session_name, NULL, &handle);
	if (ret < 0) {
		switch (-ret) {
		case LTTNG_ERR_SESSION_NOT_STARTED:
			WARN("Tracing session %s not started yet", session_name);
			cmd_ret = CMD_WARNING;
			goto end;
		default:
			ERR("%s", lttng_strerror(ret));
			goto error;
		}
	}

	if (opt_no_wait) {
		rotation_state = LTTNG_ROTATION_STATE_ONGOING;
		goto skip_wait;
	}

	_MSG("Waiting for rotation to complete");
	ret = fflush(stdout);
	if (ret) {
		PERROR("fflush");
		goto error;
	}

	do {
		rotation_status = lttng_rotation_handle_get_state(handle,
				&rotation_state);
		if (rotation_status != LTTNG_ROTATION_STATUS_OK) {
			MSG("");
			ERR("Failed to query the state of the rotation.");
			goto error;
		}

		if (rotation_state == LTTNG_ROTATION_STATE_ONGOING) {
			ret = usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME_US);
			if (ret) {
				PERROR("\nusleep");
				goto error;
			}
			_MSG(".");

			ret = fflush(stdout);
			if (ret) {
				PERROR("\nfflush");
				goto error;
			}
		}
	} while (rotation_state == LTTNG_ROTATION_STATE_ONGOING);
	MSG("");

skip_wait:
	switch (rotation_state) {
	case LTTNG_ROTATION_STATE_COMPLETED:
		rotation_status = lttng_rotation_handle_get_archive_location(
				handle, &location);
		if (rotation_status != LTTNG_ROTATION_STATUS_OK) {
			ERR("Failed to retrieve the rotation's completed chunk archive location.");
			cmd_ret = CMD_ERROR;
		}
		break;
	case LTTNG_ROTATION_STATE_EXPIRED:
		break;
	case LTTNG_ROTATION_STATE_ERROR:
		ERR("Failed to retrieve rotation state.");
		goto error;
	case LTTNG_ROTATION_STATE_ONGOING:
		MSG("Rotation ongoing for session %s", session_name);
		print_location = false;
		break;
	default:
		ERR("Unexpected rotation state encountered.");
		goto error;
	}

	if (!lttng_opt_mi && print_location) {
		ret = print_trace_archive_location(location,
				session_name);
	} else if (lttng_opt_mi) {
		ret = mi_lttng_rotate(writer, session_name, rotation_state,
				location);
	}

	if (ret < 0) {
		cmd_ret = CMD_ERROR;
	}

end:
	lttng_rotation_handle_destroy(handle);
	return cmd_ret;
error:
	cmd_ret = CMD_ERROR;
	goto end;
}

/*
 *  cmd_rotate
 *
 *  The 'rotate <options>' first level command
 */
int cmd_rotate(int argc, const char **argv)
{
	int opt, ret;
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	int popt_ret;
	static poptContext pc;
	char *session_name = NULL;
	bool free_session_name = false;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	popt_ret = poptReadDefaultConfig(pc, 0);
	if (popt_ret) {
		ERR("poptReadDefaultConfig");
		goto error;
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			cmd_ret = CMD_UNDEFINED;
			goto end;
		}
	}

	opt_session_name = (char*) poptGetArg(pc);

	if (!opt_session_name) {
		session_name = get_session_name();
		if (!session_name) {
			goto error;
		}
		free_session_name = true;
	} else {
		session_name = opt_session_name;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			goto error;
		}

		/* Open rotate command */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_rotate);
		if (ret) {
			goto error;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			goto error;
		}
	}

	cmd_ret = rotate_tracing(session_name);

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto error;
		}
		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success,
				cmd_ret == CMD_SUCCESS);
		if (ret) {
			goto error;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			goto error;
		}
	}

	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		goto error;
	}
end:
	poptFreeContext(pc);
	if (free_session_name) {
		free(session_name);
	}

	return cmd_ret;
error:
	cmd_ret = CMD_ERROR;
	goto end;
}
