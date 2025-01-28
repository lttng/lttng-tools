/*
 * SPDX-FileCopyrightText: 2011 Nils Carlson
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

/* This test generates a single event and exits.
 */

#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_tests_exitfast.h"

int main(int argc, char *argv[])
{
	int suicide = 0;
	char normal_exit_text[] = "exit-fast tracepoint normal exit";
	char suicide_exit_text[] = "exit-fast tracepoint suicide";

	if (argc > 1 && !strcmp(argv[1], "suicide")) {
		suicide = 1;
	}

	if (suicide) {
		tracepoint(ust_tests_exitfast, message, suicide_exit_text);
		kill(getpid(), SIGKILL);
	}

	tracepoint(ust_tests_exitfast, message, normal_exit_text);
	return 0;
}
