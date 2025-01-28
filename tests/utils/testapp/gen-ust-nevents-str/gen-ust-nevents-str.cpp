/*
 * SPDX-FileCopyrightText: 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "signal-helper.hpp"

#include <stdio.h>

#define TRACEPOINT_DEFINE
#include "tp.h"

int main(int argc, char **argv)
{
	int count = 0, i = 0, arg_i = 0;

	if (set_signal_handler()) {
		return 1;
	}

	if (argc <= 3) {
		fprintf(stderr, "Usage: %s COUNT STRING [STRING]...\n", argv[0]);
		return 1;
	}

	if (argc >= 2) {
		count = atoi(argv[1]);
	}

	if (count < 0) {
		return 0;
	}

	for (i = 0, arg_i = 2; i < count; i++) {
		tracepoint(tp, the_string, i, arg_i, argv[arg_i]);

		arg_i++;
		if (arg_i == argc) {
			arg_i = 2;
		}
		if (should_quit) {
			break;
		}
	}

	return 0;
}
