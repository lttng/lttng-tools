/*
 * SPDX-FileCopyrightText: 2017 Julien Desfossez <jdesfossez@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <lttng/lttng.h>

#include <ctype.h>
#include <inttypes.h>
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
#include <lttng-rotate.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "no-wait", 'n', POPT_ARG_VAL, &opt_no_wait, 1, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

static int rotate_tracing(char *session_name)
{
	int ret;
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	struct lttng_rotation_handle *handle = nullptr;
	enum lttng_rotation_status rotation_status;
	enum lttng_rotation_state rotation_state = LTTNG_ROTATION_STATE_ONGOING;
	const struct lttng_trace_archive_location *location = nullptr;
	bool print_location = true;

	DBG("Rotating the output files of session %s", session_name);

	ret = lttng_rotate_session(session_name, nullptr, &handle);
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
		rotation_status = lttng_rotation_handle_get_state(handle, &rotation_state);
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
		rotation_status = lttng_rotation_handle_get_archive_location(handle, &location);
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
		ret = print_trace_archive_location(location, session_name);
	} else if (lttng_opt_mi) {
		ret = mi_lttng_rotate(writer, session_name, rotation_state, location);
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
	const char *arg_session_name = nullptr;
	char *session_name = nullptr;

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	popt_ret = poptReadDefaultConfig(pc, 0);
	if (popt_ret) {
		ERR("poptReadDefaultConfig");
		cmd_ret = CMD_ERROR;
		goto end;
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

	arg_session_name = poptGetArg(pc);
	if (arg_session_name == nullptr) {
		session_name = get_session_name();
	} else {
		session_name = strdup(arg_session_name);
		if (session_name == nullptr) {
			PERROR("Failed to copy session name");
		}
	}

	if (session_name == nullptr) {
		cmd_ret = CMD_ERROR;
		goto end;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			cmd_ret = CMD_ERROR;
			goto end;
		}

		/* Open rotate command */
		ret = mi_lttng_writer_command_open(writer, mi_lttng_element_command_rotate);
		if (ret) {
			cmd_ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
		if (ret) {
			cmd_ret = CMD_ERROR;
			goto end;
		}
	}

	cmd_ret = (cmd_error_code) rotate_tracing(session_name);

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			cmd_ret = CMD_ERROR;
			goto end;
		}
		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, cmd_ret == CMD_SUCCESS);
		if (ret) {
			cmd_ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			cmd_ret = CMD_ERROR;
			goto end;
		}
	}

	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		cmd_ret = CMD_ERROR;
		goto end;
	}
end:
	free(session_name);
	poptFreeContext(pc);

	return cmd_ret;
}
