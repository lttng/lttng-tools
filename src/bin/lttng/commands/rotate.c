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

static int mi_output_rotate(const char *status, const char *path,
		const char *session_name)
{
	int ret;

	if (!lttng_opt_mi) {
		ret = 0;
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_rotation);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_session_name, session_name);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_rotate_status, status);
	if (ret) {
		goto end;
	}
	if (path) {
		ret = mi_lttng_writer_write_element_string(writer,
				config_element_path, path);
		if (ret) {
			goto end;
		}
	}
	/* Close rotation element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

static int rotate_tracing(char *session_name)
{
	int ret;
	char *path = NULL;
	struct lttng_rotation_manual_attr *attr = NULL;
	struct lttng_rotation_handle *handle = NULL;
	enum lttng_rotation_status rotation_status;

	attr = lttng_rotation_manual_attr_create();
	if (!attr) {
		goto error;
	}

	ret = lttng_rotation_manual_attr_set_session_name(attr, session_name);
	if (ret < 0) {
		goto error;
	}

	DBG("Rotating the output files of session %s", session_name);

	ret = lttng_rotate_session(attr, &handle);
	if (ret < 0) {
		switch (-ret) {
		case LTTNG_ERR_SESSION_NOT_STARTED:
			WARN("Tracing session %s not started yet", session_name);
			break;
		default:
			ERR("%s", lttng_strerror(ret));
			break;
		}
		goto error;
	}

	if (!opt_no_wait) {
		_MSG("Waiting for data availability");
		ret = fflush(stdout);
		if (ret) {
			PERROR("fflush");
			goto error;
		}
		do {
			ret = lttng_rotation_is_pending(handle);
			if (ret < 0) {
				goto error;
			}

			/*
			 * Data sleep time before retrying (in usec). Don't sleep if the call
			 * returned value indicates availability.
			 */
			if (ret) {
				int ret2;

				ret2 = usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME);
				if (ret2) {
					PERROR("usleep");
					goto error;
				}
				_MSG(".");
				ret2 = fflush(stdout);
				if (ret2) {
					PERROR("fflush");
					goto error;
				}
			}
		} while (ret == 1);
		MSG("");
	}

	rotation_status = lttng_rotation_handle_get_status(handle);
	switch(rotation_status) {
	case LTTNG_ROTATION_STATUS_COMPLETED:
		ret = lttng_rotation_handle_get_output_path(handle, &path);
		if (ret) {
			ERR("Get output path");
			goto error;
		}
		MSG("Trace chunk archive for session %s created at %s", session_name, path);
		ret = mi_output_rotate("completed", path, session_name);
		if (ret) {
			goto error;
		}
		ret = CMD_SUCCESS;
		goto end;
	case LTTNG_ROTATION_STATUS_STARTED:
		MSG("Rotation started for session %s", session_name);
		ret = mi_output_rotate("started", NULL, session_name);
		if (ret) {
			goto error;
		}
		ret = CMD_SUCCESS;
		goto end;
	case LTTNG_ROTATION_STATUS_EXPIRED:
		MSG("Session %s rotated, but handle expired", session_name);
		ret = mi_output_rotate("expired", NULL, session_name);
		if (ret) {
			goto error;
		}
		ret = CMD_SUCCESS;
		goto end;
	case LTTNG_ROTATION_STATUS_ERROR:
		MSG("An error occured while rotating session %s", session_name);
		ret = mi_output_rotate("error", NULL, session_name);
		if (ret) {
			goto error;
		}
		ret = CMD_SUCCESS;
		goto end;
	case LTTNG_ROTATION_STATUS_NO_ROTATION:
		/*
		 * This is never set as a status.
		 */
		abort();
	}

error:
	ret = CMD_ERROR;
end:
	lttng_rotation_handle_destroy(handle);
	lttng_rotation_manual_attr_destroy(attr);
	return ret;
}

/*
 *  cmd_rotate
 *
 *  The 'rotate <options>' first level command
 */
int cmd_rotate(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	int popt_ret;
	static poptContext pc;
	char *session_name = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	popt_ret = poptReadDefaultConfig(pc, 0);
	if (popt_ret) {
		ret = CMD_ERROR;
		ERR("poptReadDefaultConfig");
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
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	opt_session_name = (char*) poptGetArg(pc);

	if (opt_session_name == NULL) {
		session_name = get_session_name();
		if (session_name == NULL) {
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

		/* Open rotate command */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_rotate);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			goto end;
		}

		/* Open rotations element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_rotations);
		if (ret) {
			goto end;
		}

	}

	command_ret = rotate_tracing(session_name);

	if (command_ret) {
		ERR("%s", lttng_strerror(command_ret));
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  rotations element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
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
	free(session_name);
	return ret;
}
