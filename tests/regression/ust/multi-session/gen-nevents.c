/*
 * Copyright (C) - 2009 Pierre-Marc Fournier
 * Copyright (C) - 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) - 2012 David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
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
