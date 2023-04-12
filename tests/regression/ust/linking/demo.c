/*
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACEPOINT_DEFINE

#ifdef TEST_DYNAMIC_LINKAGE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#endif

#include "ust_tests_demo.h"
#include "ust_tests_demo2.h"
#include "ust_tests_demo3.h"

int main(int argc, char **argv)
{
	int i, netint;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	double dbl = 2.0;
	float flt = 2222.0;
	int delay = 0;

	if (argc == 2)
		delay = atoi(argv[1]);

	fprintf(stderr, "Demo program starting.\n");

	sleep(delay);

	fprintf(stderr, "Tracing... ");
	tracepoint(ust_tests_demo, starting, 123);
	for (i = 0; i < 5; i++) {
		netint = htonl(i);
		tracepoint(ust_tests_demo2, loop, i, netint, values, text, strlen(text), dbl, flt);
	}
	tracepoint(ust_tests_demo, done, 456);
	tracepoint(ust_tests_demo3, done, 42);
	fprintf(stderr, " done.\n");
	return 0;
}
