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
#include "tp.h"

static struct option long_options[] = {
	/* These options set a flag. */
	{ "iter", required_argument, nullptr, 'i' },
	{ "wait", required_argument, nullptr, 'w' },
	{ "create-in-main", required_argument, nullptr, 'm' },
	{ "wait-before-first-event", required_argument, nullptr, 'b' },
	{ nullptr, 0, nullptr, 0 }
};

int main(int argc, char **argv)
{
	int i, netint, ret = 0, option_index, option;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	const double dbl = 2.0;
	const float flt = 2222.0;
	unsigned int nr_iter = 100;
	useconds_t nr_usec = 0;
	char *wait_before_first_event_file_path = nullptr;
	char *create_in_main_file_path = nullptr;

	while ((option = getopt_long(argc, argv, "i:w:b:m:", long_options, &option_index)) != -1) {
		switch (option) {
		case 'b':
			wait_before_first_event_file_path = strdup(optarg);
			break;
		case 'm':
			create_in_main_file_path = strdup(optarg);
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

	if (set_signal_handler()) {
		ret = -1;
		goto end;
	}

	/*
	 * The two following sync points allow for tests to do work after the
	 * app has started BUT before it generates any events.
	 */
	if (create_in_main_file_path) {
		ret = create_file(create_in_main_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	if (wait_before_first_event_file_path) {
		ret = wait_on_file(wait_before_first_event_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	for (i = 0; i < nr_iter; i++) {
		netint = htonl(i);
		tracepoint(tp, tptest1, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest2, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest3, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest4, i, netint, values, text, strlen(text), dbl, flt);
		tracepoint(tp, tptest5, i, netint, values, text, strlen(text), dbl, flt);
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

end:
	free(create_in_main_file_path);
	free(wait_before_first_event_file_path);
	exit(!ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
