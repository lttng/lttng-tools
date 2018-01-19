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

#include <common/sessiond-comm/sessiond-comm.h>
#include <common/mi-lttng.h>
#include <common/utils.h>

#include "../command.h"
#include <lttng/rotation.h>

static char *opt_session_name;
static struct mi_writer *writer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-enable-rotation.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_TIMER,
	OPT_SIZE,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",        'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"session",     's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"timer",        0,   POPT_ARG_INT, 0, OPT_TIMER, 0, 0},
	{"size",         0,   POPT_ARG_INT, 0, OPT_SIZE, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

static int setup_rotate(char *session_name, uint64_t timer, uint64_t size)
{
	int ret = 0;
	struct lttng_rotation_schedule_attr *attr = NULL;

	attr = lttng_rotation_schedule_attr_create();
	if (!attr) {
		goto error;
	}

	ret = lttng_rotation_schedule_attr_set_session_name(attr, session_name);
	if (ret < 0) {
		goto error;
	}

	if (lttng_opt_mi) {
		/* Open rotation_schedule element */
		ret = mi_lttng_writer_open_element(writer,
				config_element_rotation_schedule);
		if (ret) {
			goto error;
		}

		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_session_name, session_name);
		if (ret) {
			goto error;
		}
	}

	if (timer) {
		lttng_rotation_schedule_attr_set_timer_period(attr, timer);
		MSG("Configuring session %s to rotate every %" PRIu64 " us",
				session_name, timer);
		if (lttng_opt_mi) {
			ret = mi_lttng_writer_write_element_unsigned_int(writer,
					config_element_rotation_timer_interval, timer);
			if (ret) {
				goto end;
			}
		}
	}
	if (size) {
		lttng_rotation_schedule_attr_set_size(attr, size);
		MSG("Configuring session %s to rotate every %" PRIu64 " bytes written",
				session_name, size);
		if (lttng_opt_mi) {
			ret = mi_lttng_writer_write_element_unsigned_int(writer,
					config_element_rotation_size, size);
			if (ret) {
				goto end;
			}
		}
	}

	ret = lttng_rotation_set_schedule(attr);
	if (ret) {
		ERR("%s", lttng_strerror(ret));
		if (lttng_opt_mi) {
			ret = mi_lttng_writer_write_element_string(writer,
					mi_lttng_element_rotate_status, "error");
			if (ret) {
				goto end;
			}
			/* Close rotation_schedule element */
			ret = mi_lttng_writer_close_element(writer);
			if (ret) {
				goto end;
			}
		}
		goto error;
	}

	if (lttng_opt_mi) {
		ret = mi_lttng_writer_write_element_string(writer,
				mi_lttng_element_rotate_status, "success");
		if (ret) {
			goto end;
		}

		/* Close rotation_schedule element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}

/*
 *  cmd_enable_rotation
 *
 *  The 'enable-rotation <options>' first level command
 */
int cmd_enable_rotation(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	int popt_ret;
	static poptContext pc;
	char *session_name = NULL;
	char *opt_arg = NULL;
	bool free_session_name = false;
	uint64_t timer = 0, size = 0;

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
		case OPT_TIMER:
			errno = 0;
			opt_arg = poptGetOptArg(pc);
			if (errno != 0 || !isdigit(opt_arg[0])) {
				ERR("Wrong value for --timer option: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			if (utils_parse_time_suffix(opt_arg, &timer) < 0 || timer == 0) {
				ERR("Wrong value for --timer option: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			DBG("Rotation timer set to %" PRIu64, timer);
			break;
		case OPT_SIZE:
			errno = 0;
			opt_arg = poptGetOptArg(pc);
			if (utils_parse_size_suffix(opt_arg, &size) < 0 || !size) {
				ERR("Wrong value for --size option: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			DBG("Rotation size set to %" PRIu64, size);
			break;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (opt_session_name == NULL) {
		session_name = get_session_name();
		if (session_name == NULL) {
			goto end;
		}
		free_session_name = true;
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
				mi_lttng_element_command_enable_rotation);
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

	/* No config options, just rotate the session now */
	if (timer == 0 && size == 0) {
		ERR("No timer or size given");
		success = 0;
		command_ret = -1;
	} else {
		command_ret = setup_rotate(session_name, timer, size);
	}

	if (command_ret) {
		ERR("%s", lttng_strerror(command_ret));
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
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
	if (free_session_name) {
		free(session_name);
	}
	return ret;
}
