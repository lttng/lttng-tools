/*
 * Copyright (C) - 2017 Philippe Proulx <pproulx@efficios.com>
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
#include <stdio.h>

#define TRACEPOINT_DEFINE
#include "tp.h"

int main(int argc, char **argv)
{
	int count;
	int i;
	int arg_i;

	if (argc <= 3) {
		fprintf(stderr, "Usage: %s COUNT STRING [STRING]...\n",
			argv[0]);
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
	}

	return 0;
}
