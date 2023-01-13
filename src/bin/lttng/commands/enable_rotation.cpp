/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/utils.hpp>

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
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "session", 's', POPT_ARG_STRING, &opt_session_name, 0, nullptr, nullptr },
	{ "timer", 0, POPT_ARG_INT, nullptr, OPT_TIMER, nullptr, nullptr },
	{ "size", 0, POPT_ARG_INT, nullptr, OPT_SIZE, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

static const char *schedule_type_str[] = {
	"size-based",
	"periodic",
};

static enum cmd_error_code add_schedule(const char *session_name,
					enum lttng_rotation_schedule_type schedule_type,
					uint64_t value)
{
	enum cmd_error_code ret = CMD_SUCCESS;
	struct lttng_rotation_schedule *schedule = nullptr;
	enum lttng_rotation_status status;
	const char *schedule_type_name;

	switch (schedule_type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		schedule = lttng_rotation_schedule_periodic_create();
		if (!schedule) {
			ret = CMD_ERROR;
			goto end;
		}
		status = lttng_rotation_schedule_periodic_set_period(schedule, value);
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		schedule = lttng_rotation_schedule_size_threshold_create();
		if (!schedule) {
			ret = CMD_ERROR;
			goto end;
		}
		status = lttng_rotation_schedule_size_threshold_set_threshold(schedule, value);
		break;
	default:
		ERR("Unknown schedule type");
		abort();
	}

	schedule_type_name = schedule_type_str[schedule_type];

	switch (status) {
	case LTTNG_ROTATION_STATUS_OK:
		break;
	case LTTNG_ROTATION_STATUS_INVALID:
		ERR("Invalid value for %s option", schedule_type_name);
		ret = CMD_ERROR;
		goto end;
	default:
		ERR("Unknown error occurred setting %s rotation schedule", schedule_type_name);
		ret = CMD_ERROR;
		goto end;
	}

	status = lttng_session_add_rotation_schedule(session_name, schedule);
	switch (status) {
	case LTTNG_ROTATION_STATUS_OK:
		ret = CMD_SUCCESS;
		switch (schedule_type) {
		case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
			MSG("Enabled %s rotations every %" PRIu64 " %s on session %s",
			    schedule_type_name,
			    value,
			    USEC_UNIT,
			    session_name);
			break;
		case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
			MSG("Enabled %s rotations every %" PRIu64 " bytes written on session %s",
			    schedule_type_name,
			    value,
			    session_name);
			break;
		default:
			abort();
		}
		break;
	case LTTNG_ROTATION_STATUS_INVALID:
		ERR("Invalid parameter for %s rotation schedule", schedule_type_name);
		ret = CMD_ERROR;
		break;
	case LTTNG_ROTATION_STATUS_SCHEDULE_ALREADY_SET:
		ERR("A %s rotation schedule is already set on session %s",
		    schedule_type_name,
		    session_name);
		ret = CMD_ERROR;
		break;
	case LTTNG_ROTATION_STATUS_ERROR:
	default:
		ERR("Failed to enable %s rotation schedule on session %s",
		    schedule_type_name,
		    session_name);
		ret = CMD_ERROR;
		break;
	}

	if (lttng_opt_mi) {
		int mi_ret;

		mi_ret = mi_lttng_rotation_schedule_result(writer, schedule, ret == CMD_SUCCESS);
		if (mi_ret < 0) {
			ret = CMD_ERROR;
			goto end;
		}
	}

end:
	lttng_rotation_schedule_destroy(schedule);
	return ret;
}

/*
 *  cmd_enable_rotation
 *
 *  The 'enable-rotation <options>' first level command
 */
int cmd_enable_rotation(int argc, const char **argv)
{
	int popt_ret, opt, ret = 0;
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = nullptr;
	char *opt_arg = nullptr;
	bool free_session_name = false;
	uint64_t timer_us = 0, size_bytes = 0;
	bool periodic_rotation = false, size_rotation = false;

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	popt_ret = poptReadDefaultConfig(pc, 0);
	if (popt_ret) {
		ERR("poptReadDefaultConfig");
		goto error;
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		if (opt_arg) {
			free(opt_arg);
			opt_arg = nullptr;
		}
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
				ERR("Invalid value for --timer option: %s", opt_arg);
				goto error;
			}
			if (utils_parse_time_suffix(opt_arg, &timer_us) < 0) {
				ERR("Invalid value for --timer option: %s", opt_arg);
				goto error;
			}
			if (periodic_rotation) {
				ERR("Only one periodic rotation schedule may be set on a session.");
				goto error;
			}
			periodic_rotation = true;
			break;
		case OPT_SIZE:
			errno = 0;
			opt_arg = poptGetOptArg(pc);
			if (utils_parse_size_suffix(opt_arg, &size_bytes) < 0) {
				ERR("Invalid value for --size option: %s", opt_arg);
				goto error;
			}
			if (size_rotation) {
				ERR("Only one size-based rotation schedule may be set on a session.");
				goto error;
			}
			size_rotation = true;
			break;
		default:
			cmd_ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (opt_session_name == nullptr) {
		session_name = get_session_name();
		if (session_name == nullptr) {
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

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
						   mi_lttng_element_command_enable_rotation);
		if (ret) {
			goto error;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
		if (ret) {
			goto error;
		}
	}

	if (!periodic_rotation && !size_rotation) {
		ERR("No session rotation schedule parameter provided.");
		cmd_ret = CMD_ERROR;
		goto close_command;
	}

	if (lttng_opt_mi) {
		ret = mi_lttng_writer_open_element(writer,
						   mi_lttng_element_rotation_schedule_results);
		if (ret) {
			goto error;
		}

		ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_session_name, session_name);
		if (ret) {
			goto error;
		}
	}

	if (periodic_rotation) {
		/*
		 * Continue processing even on error as multiple schedules can
		 * be specified at once.
		 */
		cmd_ret =
			add_schedule(session_name, LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC, timer_us);
	}

	if (size_rotation) {
		enum cmd_error_code tmp_ret;

		/* Don't overwrite cmd_ret if it already indicates an error. */
		tmp_ret = add_schedule(
			session_name, LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD, size_bytes);
		cmd_ret = cmd_ret ? cmd_ret : tmp_ret;
	}

	if (lttng_opt_mi) {
		/* Close rotation schedule results element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto error;
		}
	}

close_command:
	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto error;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, cmd_ret == CMD_SUCCESS);
		if (ret) {
			goto error;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			goto error;
		}
	}

end:
	(void) mi_lttng_writer_destroy(writer);
	poptFreeContext(pc);
	if (free_session_name) {
		free(session_name);
	}
	free(opt_arg);
	return cmd_ret;

error:
	cmd_ret = CMD_ERROR;
	goto end;
}
