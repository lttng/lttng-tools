/*
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "signal-helper.hpp"
#include "utils.h"

#include <common/string-utils/c-string-view.hpp>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACEPOINT_DEFINE
#include "gen-ust-events-tp.h"

namespace {
struct option long_options[] = {
	/* These options set a flag. */
	{ "iter", required_argument, nullptr, 'i' },
	{ "wait", required_argument, nullptr, 'w' },
	{ "sync-application-in-main-touch", required_argument, nullptr, 'a' },
	{ "sync-before-first-event", required_argument, nullptr, 'b' },
	{ "sync-after-first-event", required_argument, nullptr, 'c' },
	{ "sync-before-last-event", required_argument, nullptr, 'd' },
	{ "sync-before-last-event-touch", required_argument, nullptr, 'e' },
	{ "sync-before-exit", required_argument, nullptr, 'f' },
	{ "sync-before-exit-touch", required_argument, nullptr, 'g' },
	{ "emit-end-event", no_argument, nullptr, 'h' },
	{ "sync-after-each-iter", required_argument, nullptr, 'j' },
	{ "emit-event-with-empty-field-name", no_argument, nullptr, 0 },
	{ "text-size", required_argument, nullptr, 0 },
	{ "fill-text", no_argument, nullptr, 0 },
	{ nullptr, 0, nullptr, 0 }
};

std::string generate_repeating_test_pattern(std::size_t desired_length = sizeof("test") - 1)
{
	const auto test_string = "test";
	const auto test_string_length = lttng::c_string_view(test_string).len();

	std::string result;
	result.reserve(desired_length);

	auto remaining_length = desired_length;
	while (remaining_length) {
		const auto length_to_append = std::min(remaining_length, test_string_length);

		result.append(test_string, length_to_append);
		remaining_length -= length_to_append;
	}

	return result;
}
} /* namespace */

int main(int argc, char **argv)
{
	const char *cmd_name = (argc > 0) ? basename(argv[0]) : "COMMAND";
	unsigned int i, netint, text_size = 10;
	bool fill_text = false;
	int option_index;
	int option;
	long values[] = { 1, 2, 3 };
	std::string test_text;
	const char escape[10] = "\\*";
	const double dbl = 2.0;
	const float flt = 2222.0;
	uint32_t net_values[] = { 1, 2, 3 };
	int nr_iter = 100, ret = 0, first_event_file_created = 0;
	useconds_t nr_usec = 0;
	char *application_in_main_file_path = nullptr;
	char *before_first_event_file_path = nullptr;
	char *after_first_event_file_path = nullptr;
	char *before_last_event_file_path = nullptr;
	char *after_each_iter_file_path = nullptr;

	/*
	 * Touch a file to indicate that all events except one were
	 * generated.
	 */
	char *before_last_event_file_path_touch = nullptr;
	/* Touch file when we are exiting */
	char *before_exit_file_path_touch = nullptr;
	/* Wait on file before exiting */
	char *before_exit_file_path = nullptr;
	/* Emit an end event */
	bool emit_end_event = false;
	bool emit_event_with_empty_field_name = false;

	for (i = 0; i < 3; i++) {
		net_values[i] = htonl(net_values[i]);
	}

	while ((option = getopt_long(
			argc, argv, "i:w:a:b:c:d:e:f:g:h:j", long_options, &option_index)) != -1) {
		switch (option) {
		case 0:
			if (strcmp(long_options[option_index].name, "text-size") == 0) {
				text_size = atoi(optarg);
			}
			if (strcmp(long_options[option_index].name, "fill-text") == 0) {
				fill_text = true;
			}
			if (strcmp(long_options[option_index].name,
				   "emit-event-with-empty-field-name") == 0) {
				emit_event_with_empty_field_name = true;
			}
			break;
		case 'a':
			application_in_main_file_path = strdup(optarg);
			break;
		case 'b':
			before_first_event_file_path = strdup(optarg);
			break;
		case 'c':
			after_first_event_file_path = strdup(optarg);
			break;
		case 'd':
			before_last_event_file_path = strdup(optarg);
			break;
		case 'e':
			before_last_event_file_path_touch = strdup(optarg);
			break;
		case 'f':
			before_exit_file_path = strdup(optarg);
			break;
		case 'g':
			before_exit_file_path_touch = strdup(optarg);
			break;
		case 'h':
			emit_end_event = true;
			break;
		case 'i':
			nr_iter = atoi(optarg);
			break;
		case 'j':
			after_each_iter_file_path = strdup(optarg);
			break;
		case 'w':
			nr_usec = atoi(optarg);
			break;
		case '?':
			/* getopt_long already printed an error message. */
		default:
			ret = -1;
			goto end;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Error: takes long options only.\n");

		/*
		 * Aborting the test program for now because callers typically don't check
		 * the test program return value, and the transition from positional
		 * arguments to getopt causes hangs when caller scripts are not updated.
		 * An abort is easier to diagnose and fix. This is a temporary solution:
		 * we should eventually ensure that all scripts test and report the test
		 * app return values.
		 */
		abort();

		ret = -1;
		goto end;
	}

	if (fill_text) {
		test_text = generate_repeating_test_pattern(text_size);
	} else {
		/* Only repeat the test pattern once. */
		test_text = generate_repeating_test_pattern();
	}

	if (set_signal_handler()) {
		ret = -1;
		goto end;
	}

	fprintf(stderr, "%s: starting: %d iter %d usec wait\n", cmd_name, nr_iter, nr_usec);

	/*
	 * The two following sync points allow for tests to do work after the
	 * app has started BUT before it generates any events.
	 */
	if (application_in_main_file_path) {
		fprintf(stderr,
			"%s: sync-application-in-main-touch: create %s\n",
			cmd_name,
			application_in_main_file_path);
		ret = create_file(application_in_main_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	if (before_first_event_file_path) {
		fprintf(stderr,
			"%s: sync-before-first-event: wait %s\n",
			cmd_name,
			before_first_event_file_path);
		ret = wait_on_file(before_first_event_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	for (i = 0; nr_iter < 0 || i < nr_iter; i++) {
		if (nr_iter >= 0 && i == nr_iter - 1) {
			if (before_last_event_file_path_touch) {
				fprintf(stderr,
					"%s: sync-before-last-event-touch: create %s\n",
					cmd_name,
					before_last_event_file_path_touch);
				ret = create_file(before_last_event_file_path_touch);
				if (ret != 0) {
					goto end;
				}
			}

			/*
			 * Wait on synchronization before writing last
			 * event.
			 */
			if (before_last_event_file_path) {
				fprintf(stderr,
					"%s: sync-before-last-event: wait %s\n",
					cmd_name,
					before_last_event_file_path);
				ret = wait_on_file(before_last_event_file_path);
				if (ret != 0) {
					goto end;
				}
			}
		}
		netint = htonl(i);
		tracepoint(tp,
			   tptest,
			   i,
			   netint,
			   values,
			   test_text.c_str(),
			   test_text.size(),
			   escape,
			   net_values,
			   dbl,
			   flt);

		/*
		 * First loop we create the file if asked to indicate
		 * that at least one tracepoint has been hit.
		 */
		if (after_first_event_file_path && first_event_file_created == 0) {
			fprintf(stderr,
				"%s: sync-after-first-event: create %s\n",
				cmd_name,
				after_first_event_file_path);
			ret = create_file(after_first_event_file_path);

			if (ret != 0) {
				goto end;
			} else {
				first_event_file_created = 1;
			}
		}

		if (nr_usec) {
			if (usleep_safe(nr_usec)) {
				ret = -1;
				goto end;
			}
		}

		if (after_each_iter_file_path) {
			fprintf(stderr,
				"%s: sync-after-each-iter: wait %s\n",
				cmd_name,
				after_each_iter_file_path);
			ret = wait_on_file(after_each_iter_file_path);
			if (ret != 0) {
				goto end;
			}

			fprintf(stderr,
				"%s: sync-after-each-iter: delete %s\n",
				cmd_name,
				after_each_iter_file_path);
			ret = delete_file(after_each_iter_file_path);
			if (ret != 0) {
				goto end;
			}
		}

		if (should_quit) {
			break;
		}
	}

	if (emit_event_with_empty_field_name) {
		tracepoint(tp, tptest_empty, 1);
	}

	if (emit_end_event) {
		tracepoint(tp, end);
	}

	if (before_exit_file_path_touch) {
		fprintf(stderr,
			"%s: sync-before-exit-touch: create %s\n",
			cmd_name,
			before_exit_file_path_touch);
		ret = create_file(before_exit_file_path_touch);
		if (ret != 0) {
			goto end;
		}
	}
	if (before_exit_file_path) {
		fprintf(stderr, "%s: sync-before-exit: wait %s\n", cmd_name, before_exit_file_path);
		ret = wait_on_file(before_exit_file_path);
		if (ret != 0) {
			goto end;
		}
	}
end:
	free(after_each_iter_file_path);
	free(application_in_main_file_path);
	free(before_first_event_file_path);
	free(after_first_event_file_path);
	free(before_last_event_file_path);
	free(before_last_event_file_path_touch);
	free(before_exit_file_path);
	free(before_exit_file_path_touch);
	exit(!ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
