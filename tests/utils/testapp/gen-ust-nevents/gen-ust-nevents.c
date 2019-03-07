/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "utils.h"
#include "signal-helper.h"

#define TRACEPOINT_DEFINE
#include "tp.h"

int main(int argc, char **argv)
{
	int i, netint, ret = 0;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	double dbl = 2.0;
	float flt = 2222.0;
	unsigned int nr_iter = 100;
	useconds_t nr_usec = 0;

	if (set_signal_handler()) {
		ret = -1;
		goto end;
	}

	if (argc >= 2) {
		nr_iter = atoi(argv[1]);
	}

	if (argc == 3) {
		/* By default, don't wait unless user specifies. */
		nr_usec = atoi(argv[2]);
	}

	for (i = 0; i < nr_iter; i++) {
		netint = htonl(i);
		tracepoint(tp, tptest1, i, netint, values, text, strlen(text),
			   dbl, flt);
		tracepoint(tp, tptest2, i, netint, values, text, strlen(text),
				dbl, flt);
		tracepoint(tp, tptest3, i, netint, values, text, strlen(text),
				dbl, flt);
		tracepoint(tp, tptest4, i, netint, values, text, strlen(text),
				dbl, flt);
		tracepoint(tp, tptest5, i, netint, values, text, strlen(text),
				dbl, flt);
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
        exit(!ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
