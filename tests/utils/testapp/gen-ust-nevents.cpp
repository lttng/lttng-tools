/*
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "signal-helper.hpp"
#include "utils.h"

#include <arpa/inet.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACEPOINT_DEFINE
#include "gen-ust-nevents-tp.h"

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
	{ "sync-after-each-iter", required_argument, nullptr, 'j' },
	{ nullptr, 0, nullptr, 0 }
};
} /* namespace */

int main(int argc, char **argv)
{
	unsigned int i, netint;
	int option_index;
	int option;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	const double dbl = 2.0;
	const float flt = 2222.0;
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

	while ((option = getopt_long(
			argc, argv, "i:w:a:b:c:d:e:f:g:j", long_options, &option_index)) != -1) {
		switch (option) {
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

	if (set_signal_handler()) {
		ret = -1;
		goto end;
	}

	/*
	 * The two following sync points allow for tests to do work after the
	 * app has started BUT before it generates any events.
	 */
	if (application_in_main_file_path) {
		ret = create_file(application_in_main_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	if (before_first_event_file_path) {
		ret = wait_on_file(before_first_event_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	for (i = 0; nr_iter < 0 || i < nr_iter; i++) {
		if (nr_iter >= 0 && i == nr_iter - 1) {
			if (before_last_event_file_path_touch) {
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
				ret = wait_on_file(before_last_event_file_path);
				if (ret != 0) {
					goto end;
				}
			}
		}

		netint = htonl(i);

		tracepoint(tp, tptest1, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest2, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest3, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest4, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest5, i, netint, values, text, strlen(text), dbl, flt);

		/*
		 * First loop we create the file if asked to indicate
		 * that at least one tracepoint has been hit.
		 */
		if (after_first_event_file_path && first_event_file_created == 0) {
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
			ret = wait_on_file(after_each_iter_file_path);
			if (ret != 0) {
				goto end;
			}

			ret = delete_file(after_each_iter_file_path);
			if (ret != 0) {
				goto end;
			}
		}

		if (should_quit) {
			break;
		}
	}

	if (before_exit_file_path_touch) {
		ret = create_file(before_exit_file_path_touch);
		if (ret != 0) {
			goto end;
		}
	}
	if (before_exit_file_path) {
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
