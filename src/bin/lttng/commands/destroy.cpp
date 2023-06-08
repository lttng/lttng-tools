/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/exception.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/mi-lttng.hpp>
#include <common/scope-exit.hpp>
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
cmd_error_code destroy_session(const lttng_session& session)
{
	int ret;
	bool newline_needed = false, printed_destroy_msg = false;

	const auto print_trailing_new_line = lttng::make_scope_exit([&newline_needed]() noexcept {
		if (newline_needed) {
			MSG("");
		}
	});

	ret = lttng_stop_tracing_no_wait(session.name);
	if (ret < 0 && ret != -LTTNG_ERR_TRACE_ALREADY_STOPPED) {
		LTTNG_THROW_CTL(lttng::format("Failed to stop session `{}`", session.name),
				static_cast<lttng_error_code>(-ret));
	}

	const auto session_was_already_stopped = ret == -LTTNG_ERR_TRACE_ALREADY_STOPPED;
	if (!opt_no_wait) {
		do {
			ret = lttng_data_pending(session.name);
			if (ret < 0) {
				/* Return the data available call error. */
				ERR_FMT("Failed to check pending data for session `{}` ({})",
					session.name,
					lttng_strerror(ret));
				return CMD_ERROR;
			}

			/*
			 * Data sleep time before retrying (in usec). Don't
			 * sleep if the call returned value indicates
			 * availability.
			 */
			if (ret) {
				if (!printed_destroy_msg) {
					_MSG("Destroying session `%s`", session.name);
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

	std::unique_ptr<char, lttng::memory::create_deleter_class<char, lttng::free>::deleter>
		stats_str;
	if (!session_was_already_stopped) {
		char *raw_stats_str = nullptr;

		/*
		 * Don't print the event and packet loss warnings since the user
		 * already saw them when stopping the trace.
		 */
		ret = get_session_stats_str(session.name, &raw_stats_str);
		if (ret < 0) {
			return CMD_ERROR;
		}

		/* May still be null if there are no stats to print. */
		stats_str.reset(raw_stats_str);
	}

	const auto destruction_handle = [&session]() {
		struct lttng_destruction_handle *raw_destruction_handle = nullptr;

		auto ctl_ret_code =
			lttng_destroy_session_ext(session.name, &raw_destruction_handle);
		if (ctl_ret_code != LTTNG_OK) {
			LTTNG_THROW_CTL(lttng::format("Failed to destroy session `{}`",
						      session.name),
					ctl_ret_code);
		}

		return lttng::make_unique_wrapper<lttng_destruction_handle,
						  lttng_destruction_handle_destroy>(
			raw_destruction_handle);
	}();

	if (!opt_no_wait) {
		enum lttng_destruction_handle_status status;

		do {
			status = lttng_destruction_handle_wait_for_completion(
				destruction_handle.get(),
				DEFAULT_DATA_AVAILABILITY_WAIT_TIME_US / USEC_PER_MSEC);
			switch (status) {
			case LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT:
				if (!printed_destroy_msg) {
					_MSG("Destroying session `%s`", session.name);
					newline_needed = true;
					printed_destroy_msg = true;
				}
				_MSG(".");
				fflush(stdout);
				break;
			case LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED:
				break;
			default:
				ERR_FMT("{}An error occurred during the destruction of session `{}`",
					newline_needed ? "\n" : "",
					session.name);
				newline_needed = false;
				return CMD_ERROR;
			}
		} while (status == LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT);

		enum lttng_error_code ctl_ret_code;
		status = lttng_destruction_handle_get_result(destruction_handle.get(),
							     &ctl_ret_code);
		if (status != LTTNG_DESTRUCTION_HANDLE_STATUS_OK) {
			ERR_FMT("{}Failed to query the result of the destruction of session `{}`",
				newline_needed ? "\n" : "",
				session.name);

			newline_needed = false;
			return CMD_ERROR;
		}

		if (ctl_ret_code != LTTNG_OK) {
			LTTNG_THROW_CTL(lttng::format("Failed to destroy session `{}`",
						      session.name),
					ctl_ret_code);
		}

		enum lttng_rotation_state rotation_state;
		status = lttng_destruction_handle_get_rotation_state(destruction_handle.get(),
								     &rotation_state);
		if (status != LTTNG_DESTRUCTION_HANDLE_STATUS_OK) {
			ERR_FMT("{}Failed to query the rotation state from the destruction handle of session `{}`",
				newline_needed ? "\n" : "",
				session.name);
			newline_needed = false;
		} else {
			switch (rotation_state) {
			case LTTNG_ROTATION_STATE_NO_ROTATION:
				break;
			case LTTNG_ROTATION_STATE_COMPLETED:
			{
				const struct lttng_trace_archive_location *location;

				status = lttng_destruction_handle_get_archive_location(
					destruction_handle.get(), &location);
				if (status == LTTNG_DESTRUCTION_HANDLE_STATUS_OK) {
					ret = print_trace_archive_location(location, session.name);
					if (ret) {
						ERR_FMT("{}Failed to print the location of the latest trace archive of session `{}`",
							newline_needed ? "\n" : "",
							session.name);
						newline_needed = false;
					}

					break;
				}
			}
			/* fall-through. */
			default:
				ERR_FMT("{}Failed to get the location of the rotation performed during the destruction of `{}`",
					newline_needed ? "\n" : "",
					session.name);
				newline_needed = false;
				break;
			}
		}
	}

	MSG("%sSession `%s` destroyed", newline_needed ? "\n" : "", session.name);
	newline_needed = false;
	if (stats_str) {
		MSG("%s", stats_str.get());
	}

	/*
	 * If the session being destroy is the "default" session as defined in the .lttngrc file,
	 * destroy the file.
	 */
	const auto session_name =
		lttng::make_unique_wrapper<char, lttng::free>(get_session_name_quiet());
	if (session_name && !strncmp(session.name, session_name.get(), NAME_MAX)) {
		config_destroy_default();
	}

	if (lttng_opt_mi) {
		ret = mi_lttng_session(writer, &session, 0);
		if (ret) {
			return CMD_ERROR;
		}
	}

	return CMD_SUCCESS;
}

cmd_error_code destroy_sessions(const lttng::cli::session_spec& spec)
{
	bool had_warning = false;
	bool had_error = false;
	bool listing_failed = false;

	const auto sessions = [&listing_failed, &spec]() -> lttng::cli::session_list {
		try {
			return list_sessions(spec);
		} catch (const lttng::ctl::error& ctl_exception) {
			ERR_FMT("Failed to list sessions ({})",
				lttng_strerror(-ctl_exception.code()));
			listing_failed = true;
			return {};
		}
	}();

	if (!listing_failed && sessions.size() == 0 &&
	    spec.type_ == lttng::cli::session_spec::type::NAME) {
		ERR_FMT("Session `{}` not found", spec.value);
		return CMD_ERROR;
	}

	if (listing_failed) {
		return CMD_FATAL;
	}

	for (const auto& session : sessions) {
		cmd_error_code sub_ret;

		try {
			sub_ret = destroy_session(session);
		} catch (const lttng::ctl::error& ctl_exception) {
			switch (ctl_exception.code()) {
			case LTTNG_ERR_NO_SESSION:
				if (spec.type_ != lttng::cli::session_spec::type::NAME) {
					/* Session destroyed during command, ignore and carry-on. */
					sub_ret = CMD_SUCCESS;
					break;
				} else {
					sub_ret = CMD_ERROR;
					break;
				}
			case LTTNG_ERR_NO_SESSIOND:
				/* Don't keep going on a fatal error. */
				return CMD_FATAL;
			default:
				/* Generic error. */
				sub_ret = CMD_ERROR;
				ERR_FMT("Failed to destroy session `{}` ({})",
					session.name,
					lttng_strerror(-ctl_exception.code()));
				break;
			}
		}

		/* Keep going, but report the most serious state. */
		had_warning |= sub_ret == CMD_WARNING;
		had_error |= sub_ret == CMD_ERROR;
	}

	if (had_error) {
		return CMD_ERROR;
	} else if (had_warning) {
		return CMD_WARNING;
	} else {
		return CMD_SUCCESS;
	}
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
	lttng::cli::session_spec spec(lttng::cli::session_spec::type::NAME);
	lttng::cli::session_list const sessions;

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
			spec.type_ = lttng::cli::session_spec::type::ALL;
			break;
		case OPT_ENABLE_GLOB:
			spec.type_ = lttng::cli::session_spec::type::GLOB_PATTERN;
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
