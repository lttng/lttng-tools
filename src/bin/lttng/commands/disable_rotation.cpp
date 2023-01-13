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
#include <lttng-disable-rotation.1.h>
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
	{ "timer", 0, POPT_ARG_NONE, nullptr, OPT_TIMER, nullptr, nullptr },
	{ "size", 0, POPT_ARG_NONE, nullptr, OPT_SIZE, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

static const char *schedule_type_str[] = {
	"periodic",
	"size-based",
};

static const struct lttng_rotation_schedule *
get_schedule(const char *session_name,
	     const struct lttng_rotation_schedules *schedules,
	     enum lttng_rotation_schedule_type schedule_type)
{
	unsigned int count, i;
	enum lttng_rotation_status status;
	const struct lttng_rotation_schedule *ret = nullptr;

	status = lttng_rotation_schedules_get_count(schedules, &count);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		ERR("Unable to determine the number of rotation schedules of session %s",
		    session_name);
		goto end;
	}

	for (i = 0; i < count; i++) {
		const struct lttng_rotation_schedule *schedule = nullptr;

		schedule = lttng_rotation_schedules_get_at_index(schedules, i);
		if (!schedule) {
			ERR("Unable to retrieve rotation schedule at index %u", i);
			goto end;
		}

		if (lttng_rotation_schedule_get_type(schedule) == schedule_type) {
			ret = schedule;
			break;
		}
	}

	if (!ret) {
		ERR("No %s rotation schedule active on session %s",
		    schedule_type_str[schedule_type],
		    session_name);
	}
end:
	return ret;
}

static struct lttng_rotation_schedule *create_empty_schedule(enum lttng_rotation_schedule_type type)
{
	struct lttng_rotation_schedule *schedule = nullptr;

	switch (type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		schedule = lttng_rotation_schedule_periodic_create();
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		schedule = lttng_rotation_schedule_size_threshold_create();
		break;
	default:
		abort();
	}
	return schedule;
}

static enum cmd_error_code remove_schedule(const char *session_name,
					   enum lttng_rotation_schedule_type schedule_type)
{
	enum cmd_error_code cmd_ret;
	int ret;
	const struct lttng_rotation_schedule *schedule = nullptr;
	struct lttng_rotation_schedules *schedules = nullptr;
	enum lttng_rotation_status status;
	const char *schedule_type_name;
	struct lttng_rotation_schedule *empty_schedule = nullptr;

	switch (schedule_type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		break;
	default:
		ERR("Unknown schedule type");
		abort();
	}

	schedule_type_name = schedule_type_str[schedule_type];

	ret = lttng_session_list_rotation_schedules(session_name, &schedules);
	if (ret != LTTNG_OK) {
		ERR("Failed to list rotation schedules of session %s", session_name);
		goto error;
	}

	schedule = get_schedule(session_name, schedules, schedule_type);
	if (!schedule) {
		cmd_ret = CMD_ERROR;
		/*
		 * get_schedule() logs its own errors.
		 * A temporaty schedule is created to serialize an MI rotation
		 * schedule descriptor of the appropriate type that has no
		 * attributes set.
		 */
		empty_schedule = create_empty_schedule(schedule_type);
		if (!empty_schedule) {
			goto error;
		}
		goto skip_removal;
	}

	status = lttng_session_remove_rotation_schedule(session_name, schedule);
	switch (status) {
	case LTTNG_ROTATION_STATUS_OK:
		MSG("Disabled %s rotation on session %s", schedule_type_name, session_name);
		cmd_ret = CMD_SUCCESS;
		break;
	case LTTNG_ROTATION_STATUS_SCHEDULE_NOT_SET:
		ERR("No %s rotation schedule set on session %s", schedule_type_name, session_name);
		cmd_ret = CMD_ERROR;
		break;
	case LTTNG_ROTATION_STATUS_ERROR:
	case LTTNG_ROTATION_STATUS_INVALID:
	default:
		ERR("Failed to disable %s rotation schedule on session %s",
		    schedule_type_name,
		    session_name);
		cmd_ret = CMD_ERROR;
		break;
	}

skip_removal:
	if (lttng_opt_mi) {
		ret = mi_lttng_rotation_schedule_result(
			writer, schedule ? schedule : empty_schedule, cmd_ret == CMD_SUCCESS);
		if (ret < 0) {
			goto error;
		}
	}

end:
	lttng_rotation_schedules_destroy(schedules);
	lttng_rotation_schedule_destroy(empty_schedule);
	return cmd_ret;
error:
	cmd_ret = CMD_ERROR;
	goto end;
}

/*
 *  cmd_disable_rotation
 *
 *  The 'disable-rotation <options>' first level command
 */
int cmd_disable_rotation(int argc, const char **argv)
{
	int popt_ret, opt, ret = 0;
	enum cmd_error_code cmd_ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = nullptr;
	bool free_session_name = false;
	bool periodic_rotation = false, size_rotation = false;

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	popt_ret = poptReadDefaultConfig(pc, 0);
	if (popt_ret) {
		cmd_ret = CMD_ERROR;
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
			periodic_rotation = true;
			break;
		case OPT_SIZE:
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
						   mi_lttng_element_command_disable_rotation);
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
		ERR("No session rotation schedule type provided.");
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
		cmd_ret = remove_schedule(session_name, LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC);
	}

	if (size_rotation) {
		enum cmd_error_code tmp_ret;

		/* Don't overwrite cmd_ret if it already indicates an error. */
		tmp_ret =
			remove_schedule(session_name, LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD);
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
		/* Close  output element */
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
	return cmd_ret;
error:
	cmd_ret = CMD_ERROR;
	goto end;
}
