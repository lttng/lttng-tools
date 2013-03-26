/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011-2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_tests_daemon.h"

int main(int argc, char **argv, char *env[])
{
	int result;

	if (argc < 1) {
		fprintf(stderr, "usage: daemon\n");
		exit(1);
	}

	pid_t parent_pid = getpid();
	printf("parent_pid %d\n", parent_pid);
	tracepoint(ust_tests_daemon, before_daemon, parent_pid);

	result = daemon(0, 1);
	if (result == 0) {
		printf("child_pid %d\n", getpid());

		tracepoint(ust_tests_daemon, after_daemon_child, getpid());
	} else {
		tracepoint(ust_tests_daemon, after_daemon_parent);
		perror("daemon");
		exit(1);
	}

	return 0;
}
