/*
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_tests_fork.h"

int main(int argc, char **argv, char *env[])
{
	int result;

	if (argc < 2) {
		fprintf(stderr, "usage: fork PROG_TO_EXEC\n");
		exit(1);
	}

	printf("parent_pid %d\n", getpid());
	tracepoint(ust_tests_fork, before_fork, getpid());

	result = fork();
	if (result == -1) {
		perror("fork");
		return 1;
	}
	if (result == 0) {
		char *args[] = { (char *) "fork2", NULL };

		tracepoint(ust_tests_fork, after_fork_child, getpid());

		result = execve(argv[1], args, env);
		if (result == -1) {
			perror("execve");
			result = 1;
			goto end;
		}
	} else {
		printf("child_pid %d\n", result);
		tracepoint(ust_tests_fork, after_fork_parent, getpid());
		if (waitpid(result, NULL, 0) < 0) {
			perror("waitpid");
			result = 1;
			goto end;
		}
	}
	result = 0;
end:
	return result;
}
