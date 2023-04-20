/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"
#include "../utils.hpp"

#include <common/exception.hpp>
#include <common/mi-lttng.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_ENABLE_GLOB,
	OPT_ALL,
};

namespace {
#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-stop.1.h>
	;
#endif

int opt_no_wait;
struct mi_writer *writer;

struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "no-wait", 'n', POPT_ARG_VAL, &opt_no_wait, 1, nullptr, nullptr },
	{ "glob", 'g', POPT_ARG_NONE, nullptr, OPT_ENABLE_GLOB, nullptr, nullptr },
	{ "all", 'a', POPT_ARG_NONE, nullptr, OPT_ALL, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

/*
 * Mi print of partial session
 */
int mi_print_session(const char *session_name, int enabled)
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
int stop_tracing(const char *session_name)
{
	int ret;

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
		goto error;
	}

	if (!opt_no_wait) {
		_MSG("Waiting for data availability");
		fflush(stdout);
		do {
			ret = lttng_data_pending(session_name);
			if (ret < 0) {
				/* Return the data available call error. */
				goto error;
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
	}
error:
	return ret;
}

int stop_tracing(const struct session_spec& spec)
{
	int ret = CMD_SUCCESS;

	try {
		for (const auto& session : list_sessions(spec)) {
			int const sub_ret = stop_tracing(session.name);

			if (sub_ret != CMD_SUCCESS) {
				ret = sub_ret;
			}
		}
	} catch (lttng::ctl::error& error) {
		ret = error.code();
	}

	return ret;
}
} /* namespace */

/*
 *  cmd_stop
 *
 *  The 'stop <options>' first level command
 */
int cmd_stop(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;
	const char *leftover = nullptr;
	struct session_spec session_spec = {
		.type = session_spec::NAME,
		.value = nullptr,
	};

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		case OPT_ENABLE_GLOB:
			session_spec.type = session_spec::GLOB_PATTERN;
			break;
		case OPT_ALL:
			session_spec.type = session_spec::ALL;
			break;
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

	session_spec.value = poptGetArg(pc);

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	command_ret = stop_tracing(session_spec);
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
