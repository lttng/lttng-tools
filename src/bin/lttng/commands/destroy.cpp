/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/exception.hpp>
#include <common/mi-lttng.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/utils.hpp>

#include <lttng/lttng.h>

#include <popt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_ALL,
	OPT_ENABLE_GLOB,
};

namespace {
#ifdef LTTNG_EMBED_HELP
const char help_msg[] =
#include <lttng-destroy.1.h>
	;
#endif

int opt_no_wait;

/* Mi writer */
struct mi_writer *writer;

struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "all", 'a', POPT_ARG_NONE, nullptr, OPT_ALL, nullptr, nullptr },
	{ "glob", 'g', POPT_ARG_NONE, nullptr, OPT_ENABLE_GLOB, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "no-wait", 'n', POPT_ARG_VAL, &opt_no_wait, 1, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

/*
 * destroy_session
 *
 * Unregister the provided session to the session daemon. On success, removes
 * the default configuration.
 */
int destroy_session(const struct lttng_session& session)
{
	int ret;
	char *session_name = nullptr;
	bool session_was_already_stopped;
	enum lttng_error_code ret_code;
	struct lttng_destruction_handle *handle = nullptr;
	enum lttng_destruction_handle_status status;
	bool newline_needed = false, printed_destroy_msg = false;
	enum lttng_rotation_state rotation_state;
	char *stats_str = nullptr;

	ret = lttng_stop_tracing_no_wait(session.name);
	if (ret < 0 && ret != -LTTNG_ERR_TRACE_ALREADY_STOPPED) {
		ERR("%s", lttng_strerror(ret));
	}

	session_was_already_stopped = ret == -LTTNG_ERR_TRACE_ALREADY_STOPPED;
	if (!opt_no_wait) {
		do {
			ret = lttng_data_pending(session.name);
			if (ret < 0) {
				/* Return the data available call error. */
				goto error;
			}

			/*
			 * Data sleep time before retrying (in usec). Don't
			 * sleep if the call returned value indicates
			 * availability.
			 */
			if (ret) {
				if (!printed_destroy_msg) {
					_MSG("Destroying session %s", session.name);
					newline_needed = true;
					printed_destroy_msg = true;
					fflush(stdout);
				}

				usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME_US);
				_MSG(".");
				fflush(stdout);
			}
		} while (ret != 0);
	}

	if (!session_was_already_stopped) {
		/*
		 * Don't print the event and packet loss warnings since the user
		 * already saw them when stopping the trace.
		 */
		ret = get_session_stats_str(session.name, &stats_str);
		if (ret < 0) {
			goto error;
		}
	}

	ret_code = lttng_destroy_session_ext(session.name, &handle);
	if (ret_code != LTTNG_OK) {
		ret = -ret_code;
		goto error;
	}

	if (opt_no_wait) {
		goto skip_wait_rotation;
	}

	do {
		status = lttng_destruction_handle_wait_for_completion(
			handle, DEFAULT_DATA_AVAILABILITY_WAIT_TIME_US / USEC_PER_MSEC);
		switch (status) {
		case LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT:
			if (!printed_destroy_msg) {
				_MSG("Destroying session %s", session.name);
				newline_needed = true;
				printed_destroy_msg = true;
			}
			_MSG(".");
			fflush(stdout);
			break;
		case LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED:
			break;
		default:
			ERR("%sFailed to wait for the completion of the destruction of session \"%s\"",
			    newline_needed ? "\n" : "",
			    session.name);
			newline_needed = false;
			ret = -1;
			goto error;
		}
	} while (status == LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT);

	status = lttng_destruction_handle_get_result(handle, &ret_code);
	if (status != LTTNG_DESTRUCTION_HANDLE_STATUS_OK) {
		ERR("%sFailed to get the result of session destruction",
		    newline_needed ? "\n" : "");
		ret = -1;
		newline_needed = false;
		goto error;
	}
	if (ret_code != LTTNG_OK) {
		ret = -ret_code;
		goto error;
	}

	status = lttng_destruction_handle_get_rotation_state(handle, &rotation_state);
	if (status != LTTNG_DESTRUCTION_HANDLE_STATUS_OK) {
		ERR("%sFailed to get rotation state from destruction handle",
		    newline_needed ? "\n" : "");
		newline_needed = false;
		goto skip_wait_rotation;
	}

	switch (rotation_state) {
	case LTTNG_ROTATION_STATE_NO_ROTATION:
		break;
	case LTTNG_ROTATION_STATE_COMPLETED:
	{
		const struct lttng_trace_archive_location *location;

		status = lttng_destruction_handle_get_archive_location(handle, &location);
		if (status == LTTNG_DESTRUCTION_HANDLE_STATUS_OK) {
			ret = print_trace_archive_location(location, session.name);
			if (ret) {
				ERR("%sFailed to print the location of trace archive",
				    newline_needed ? "\n" : "");
				newline_needed = false;
				goto skip_wait_rotation;
			}
			break;
		}
	}
	/* fall-through. */
	default:
		ERR("%sFailed to get the location of the rotation performed during the session's destruction",
		    newline_needed ? "\n" : "");
		newline_needed = false;
		goto skip_wait_rotation;
	}
skip_wait_rotation:
	MSG("%sSession %s destroyed", newline_needed ? "\n" : "", session.name);
	newline_needed = false;
	if (stats_str) {
		MSG("%s", stats_str);
	}

	session_name = get_session_name_quiet();
	if (session_name && !strncmp(session.name, session_name, NAME_MAX)) {
		config_destroy_default();
	}

	if (lttng_opt_mi) {
		ret = mi_lttng_session(writer, &session, 0);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	ret = CMD_SUCCESS;
error:
	if (newline_needed) {
		MSG("");
	}
	lttng_destruction_handle_destroy(handle);
	free(session_name);
	free(stats_str);
	return ret;
}

cmd_error_code destroy_sessions(const struct session_spec& spec)
{
	//bool had_warning = false;
	//bool had_error = false;
	bool listing_failed = false;

	const auto sessions = [&listing_failed, &spec]() -> session_list {
		try {
			return list_sessions(spec);
		} catch (const lttng::ctl::error& ctl_exception) {
			ERR_FMT("Failed to list sessions ({})",
				lttng_strerror(-ctl_exception.code()));
			listing_failed = true;
			return {};
		}
	}();

	if (sessions.size() == 0) {
		switch (spec.type) {
		case session_spec::ALL:
			/* fall-through. */
		case session_spec::GLOB_PATTERN:
			MSG("No session found, nothing to do.");
			break;
		case session_spec::NAME:
			ERR("Session name %s not found", spec.value);
			return CMD_ERROR;
		}
	}

	for (const auto& session : sessions) {
		int const sub_ret = destroy_session(session);

		if (sub_ret != CMD_SUCCESS) {
			ERR("%s during the destruction of session \"%s\"",
				lttng_strerror(sub_ret),
				session.name);
			return CMD_ERROR;
		}
	}

	return CMD_SUCCESS;
}
} /* namespace */

/*
 * The 'destroy <options>' first level command
 */
int cmd_destroy(int argc, const char **argv)
{
	int opt;
	cmd_error_code command_ret = CMD_SUCCESS;
	bool success;
	static poptContext pc;
	const char *leftover = nullptr;
	struct session_spec spec = {
		.type = session_spec::NAME,
		.value = nullptr,
	};
	session_list const sessions;

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
		{
			int ret;

			SHOW_HELP();
			command_ret = static_cast<cmd_error_code>(ret);
			goto end;
		}
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		case OPT_ALL:
			spec.type = session_spec::ALL;
			break;
		case OPT_ENABLE_GLOB:
			spec.type = session_spec::GLOB_PATTERN;
			break;
		default:
			command_ret = CMD_UNDEFINED;
			goto end;
		}
	}

	/* Mi preparation */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Open command element */
		if (mi_lttng_writer_command_open(writer, mi_lttng_element_command_destroy)) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		if (mi_lttng_writer_open_element(writer, mi_lttng_element_command_output)) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* For validation and semantic purpose we open a sessions element */
		if (mi_lttng_sessions_open(writer)) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

	spec.value = poptGetArg(pc);

	command_ret = destroy_sessions(spec);

	success = command_ret == CMD_SUCCESS;

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		command_ret = CMD_ERROR;
		success = false;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close sessions and output element element */
		if (mi_lttng_close_multi_element(writer, 2)) {
		command_ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		if (mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, success)) {
		command_ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		if (mi_lttng_writer_command_close(writer)) {
		command_ret = CMD_ERROR;
			goto end;
		}
	}
end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		command_ret = CMD_ERROR;
	}

	poptFreeContext(pc);
	return command_ret;
}
