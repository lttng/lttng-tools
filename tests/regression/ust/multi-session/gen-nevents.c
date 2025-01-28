/*
 * SPDX-FileCopyrightText: 2009 Pierre-Marc Fournier
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
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
#include "ust_gen_nevents.h"

int main(int argc, char **argv)
{
	int i, nr_iter = 100;
	long value = 42;

	if (argc == 2) {
		nr_iter = atoi(argv[1]);
	}

	for (i = 0; i < nr_iter; i++) {
		tracepoint(ust_gen_nevents, tptest0, i, value);
		tracepoint(ust_gen_nevents, tptest1, i, value);
		tracepoint(ust_gen_nevents, tptest2, i, value);
		tracepoint(ust_gen_nevents, tptest3, i, value);
	}

	return 0;
}
