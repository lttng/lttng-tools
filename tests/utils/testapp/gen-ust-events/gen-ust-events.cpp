/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "signal-helper.hpp"
#include "utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACEPOINT_DEFINE
#include "tp.h"

static struct option long_options[] = {
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
	{ nullptr, 0, nullptr, 0 }
};

int main(int argc, char **argv)
{
	unsigned int i, netint;
	int option_index;
	int option;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	char escape[10] = "\\*";
	double dbl = 2.0;
	float flt = 2222.0;
	uint32_t net_values[] = { 1, 2, 3 };
	int nr_iter = 100, ret = 0, first_event_file_created = 0;
	useconds_t nr_usec = 0;
	char *application_in_main_file_path = nullptr;
	char *before_first_event_file_path = nullptr;
	char *after_first_event_file_path = nullptr;
	char *before_last_event_file_path = nullptr;
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

	for (i = 0; i < 3; i++) {
		net_values[i] = htonl(net_values[i]);
	}

	while ((option = getopt_long(
			argc, argv, "i:w:a:b:c:d:e:f:g:h", long_options, &option_index)) != -1) {
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
		case 'h':
			emit_end_event = true;
			break;
		case 'i':
			nr_iter = atoi(optarg);
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

	if (application_in_main_file_path) {
		create_file(application_in_main_file_path);
	}

	if (before_first_event_file_path) {
		wait_on_file(before_first_event_file_path);
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
		tracepoint(tp,
			   tptest,
			   i,
			   netint,
			   values,
			   text,
			   strlen(text),
			   escape,
			   net_values,
			   dbl,
			   flt);

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
		if (should_quit) {
			break;
		}
	}

	if (emit_end_event) {
		tracepoint(tp, end);
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
	free(application_in_main_file_path);
	free(before_first_event_file_path);
	free(after_first_event_file_path);
	free(before_last_event_file_path);
	free(before_last_event_file_path_touch);
	free(before_exit_file_path);
	free(before_exit_file_path_touch);
	exit(!ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
