/*
 * Copyright (C) 2009 Pierre-Marc Fournier
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdio.h>
#include <unistd.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_tests_fork.h"

int main(int argc, char **argv)
{
	printf("IN FORK2\n");

	tracepoint(ust_tests_fork, after_exec, getpid());

	return 0;
}
