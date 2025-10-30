/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generate events using many event classes.
 */

#define _LGPL_SOURCE
#include "emit-events.h"
#include "signal-helper.hpp"
#include "utils.h"

#include <common/exception.hpp>

#include <vendor/argpar/argpar.hpp>
#include <vendor/fmt/core.h>
#include <vendor/optional.hpp>

#include <chrono>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
enum option_types {
	OPT_ITER,
	OPT_WAIT,
	OPT_SYNC_APPLICATION_IN_MAIN_TOUCH,
	OPT_SYNC_BEFORE_FIRST_EVENT,
	OPT_SYNC_AFTER_FIRST_EVENT,
	OPT_SYNC_BEFORE_LAST_EVENT,
	OPT_SYNC_BEFORE_LAST_EVENT_TOUCH,
	OPT_SYNC_BEFORE_EXIT,
	OPT_SYNC_BEFORE_EXIT_TOUCH,
	OPT_EMIT_END_EVENT,
	OPT_SYNC_AFTER_EACH_ITER,
};

struct app_config {
	/*
	 * For the purposes of this test application, an iterations implies emiting each of the
	 * events one time.
	 */
	unsigned int nr_iter = 100;
	nonstd::optional<std::chrono::microseconds> nr_usec;
	std::string application_in_main_file_path;
	std::string before_first_event_file_path;
	std::string after_first_event_file_path;
	std::string before_last_event_file_path;
	std::string before_last_event_file_path_touch;
	std::string before_exit_file_path;
	std::string before_exit_file_path_touch;
	std::string after_each_iter_file_path;
	bool emit_end_event = false;
};

app_config parse_arguments(int argc, char **argv)
{
	constexpr argpar_opt_descr options[] = {
		{ OPT_ITER, 'i', "iter", true },
		{ OPT_WAIT, 'w', "wait", true },
		{ OPT_SYNC_APPLICATION_IN_MAIN_TOUCH, 'a', "sync-application-in-main-touch", true },
		{ OPT_SYNC_BEFORE_FIRST_EVENT, 'b', "sync-before-first-event", true },
		{ OPT_SYNC_AFTER_FIRST_EVENT, 'c', "sync-after-first-event", true },
		{ OPT_SYNC_BEFORE_LAST_EVENT, 'd', "sync-before-last-event", true },
		{ OPT_SYNC_BEFORE_LAST_EVENT_TOUCH, 'e', "sync-before-last-event-touch", true },
		{ OPT_SYNC_BEFORE_EXIT, 'f', "sync-before-exit", true },
		{ OPT_SYNC_BEFORE_EXIT_TOUCH, 'g', "sync-before-exit-touch", true },
		{ OPT_EMIT_END_EVENT, 'h', "emit-end-event", false },
		{ OPT_SYNC_AFTER_EACH_ITER, 'j', "sync-after-each-iter", true },
		ARGPAR_OPT_DESCR_SENTINEL,
	};

	app_config config;

	try {
		argpar::Iter<nonstd::optional<argpar::Item>> argpar_iter(
			argc - 1, const_cast<const char **>(argv + 1), options);

		while (const auto item = argpar_iter.next()) {
			if (item->isNonOpt()) {
				LTTNG_THROW_ERROR(fmt::format("Unexpected argument: {}",
							      item->asNonOpt().arg()));
			}

			const auto& opt = item->asOpt();
			switch (opt.descr().id) {
			case OPT_ITER:
				config.nr_iter = std::atoi(opt.arg());
				break;
			case OPT_WAIT:
				config.nr_usec = std::chrono::microseconds(std::atoi(opt.arg()));
				break;
			case OPT_SYNC_APPLICATION_IN_MAIN_TOUCH:
				config.application_in_main_file_path = opt.arg();
				break;
			case OPT_SYNC_BEFORE_FIRST_EVENT:
				config.before_first_event_file_path = opt.arg();
				break;
			case OPT_SYNC_AFTER_FIRST_EVENT:
				config.after_first_event_file_path = opt.arg();
				break;
			case OPT_SYNC_BEFORE_LAST_EVENT:
				config.before_last_event_file_path = opt.arg();
				break;
			case OPT_SYNC_BEFORE_LAST_EVENT_TOUCH:
				config.before_last_event_file_path_touch = opt.arg();
				break;
			case OPT_SYNC_BEFORE_EXIT:
				config.before_exit_file_path = opt.arg();
				break;
			case OPT_SYNC_BEFORE_EXIT_TOUCH:
				config.before_exit_file_path_touch = opt.arg();
				break;
			case OPT_EMIT_END_EVENT:
				config.emit_end_event = true;
				break;
			case OPT_SYNC_AFTER_EACH_ITER:
				config.after_each_iter_file_path = opt.arg();
				break;
			default:
				break;
			}
		}
	} catch (const argpar::UnknownOptError& e) {
		LTTNG_THROW_ERROR(fmt::format("Unknown option: {}", e.name()));
	} catch (const argpar::MissingOptArgumentError& e) {
		LTTNG_THROW_ERROR(fmt::format("Missing argument for option '{}'",
					      e.descr().descr().short_name));
	} catch (const argpar::UnexpectedOptArgumentError& e) {
		LTTNG_THROW_ERROR(fmt::format("Unexpected argument for option '{}'",
					      e.descr().descr().short_name));
	}

	return config;
}

void run_application(const app_config& config)
{
	/*
	 * The two following sync points allow for tests to do work after the
	 * app has started BUT before it generates any events.
	 */
	if (!config.application_in_main_file_path.empty()) {
		const auto create_result =
			create_file(config.application_in_main_file_path.c_str());
		if (create_result != 0) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to create application ready file '{}': error code {}",
				config.application_in_main_file_path,
				create_result));
		}
	}

	if (!config.before_first_event_file_path.empty()) {
		const auto wait_result = wait_on_file(config.before_first_event_file_path.c_str());
		if (wait_result != 0) {
			LTTNG_THROW_ERROR(fmt::format("Failed to wait on file '{}': error code {}",
						      config.before_first_event_file_path,
						      wait_result));
		}
	}

	bool first_event_created = false;

	for (unsigned int i = 0; i < config.nr_iter; i++) {
		if (i == config.nr_iter - 1) {
			if (!config.before_last_event_file_path_touch.empty()) {
				const auto touch_result = create_file(
					config.before_last_event_file_path_touch.c_str());
				if (touch_result != 0) {
					LTTNG_THROW_ERROR(fmt::format(
						"Failed to create before-last-event file '{}': error code {}",
						config.before_last_event_file_path_touch,
						touch_result));
				}
			}

			/*
			 * Wait on synchronization before emitting last event.
			 */
			if (!config.before_last_event_file_path.empty()) {
				const auto wait_result =
					wait_on_file(config.before_last_event_file_path.c_str());
				if (wait_result != 0) {
					LTTNG_THROW_ERROR(fmt::format(
						"Failed to wait on before-last-event file '{}': error code {}",
						config.before_last_event_file_path,
						wait_result));
				}
			}
		}

		emit_all_events();

		/*
		 * First loop we create the file if asked to indicate
		 * that at least one tracepoint has been hit.
		 */
		if (!config.after_first_event_file_path.empty() && !first_event_created) {
			const auto create_result =
				create_file(config.after_first_event_file_path.c_str());
			if (create_result != 0) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to create after-first-event file '{}': error code {}",
					config.after_first_event_file_path,
					create_result));
			}
			first_event_created = true;
		}

		if (config.nr_usec.has_value()) {
			const auto sleep_result = usleep_safe(config.nr_usec->count());
			if (sleep_result != 0) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to sleep for {} microseconds: error code {}",
					config.nr_usec->count(),
					sleep_result));
			}
		}

		if (!config.after_each_iter_file_path.empty()) {
			const auto wait_result =
				wait_on_file(config.after_each_iter_file_path.c_str());
			if (wait_result != 0) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to wait on after-each-iter file '{}': error code {}",
					config.after_each_iter_file_path,
					wait_result));
			}

			const auto delete_result =
				delete_file(config.after_each_iter_file_path.c_str());
			if (delete_result != 0) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to delete after-each-iter file '{}': error code {}",
					config.after_each_iter_file_path,
					delete_result));
			}
		}

		if (should_quit) {
			break;
		}
	}

	if (config.emit_end_event) {
		emit_one_event();
	}

	if (!config.before_exit_file_path_touch.empty()) {
		const auto touch_result = create_file(config.before_exit_file_path_touch.c_str());
		if (touch_result != 0) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to create before-exit-touch file '{}': error code {}",
				config.before_exit_file_path_touch,
				touch_result));
		}
	}

	if (!config.before_exit_file_path.empty()) {
		const auto wait_result = wait_on_file(config.before_exit_file_path.c_str());
		if (wait_result != 0) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to wait on before-exit file '{}': error code {}",
				config.before_exit_file_path,
				wait_result));
		}
	}
}
} /* namespace */

int main(int argc, char **argv)
{
	try {
		const auto signal_handler_result = set_signal_handler();
		if (signal_handler_result != 0) {
			LTTNG_THROW_ERROR(
				fmt::format("Failed to set up signal handler: error code {}",
					    signal_handler_result));
		}

		const auto config = parse_arguments(argc, argv);
		run_application(config);

		return EXIT_SUCCESS;
	} catch (const std::exception& ex) {
		fmt::print(stderr, "Error: {}\n", ex.what());
		return EXIT_FAILURE;
	}
}
