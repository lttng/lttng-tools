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
#include "tp.h"

static void inthandler(int sig __attribute__((unused)))
{
}

static int init_int_handler(void)
{
	int result;
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	result = sigemptyset(&act.sa_mask);
	if (result == -1) {
		perror("sigemptyset");
		return -1;
	}

	act.sa_handler = inthandler;
	act.sa_flags = SA_RESTART;

	/* Only defer ourselves. Also, try to restart interrupted
	 * syscalls to disturb the traced program as little as possible.
	 */
	result = sigaction(SIGUSR1, &act, NULL);
	if (result == -1) {
		perror("sigaction");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int i, netint;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	double dbl = 2.0;
	float flt = 2222.0;
	int delay = 0;

	init_int_handler();

	if (argc == 2)
		delay = atoi(argv[1]);

	sleep(delay);

	for (i = 0; i < 1000000; i++) {
		netint = htonl(i);
		tracepoint(tp, tptest, i, netint, values, text, strlen(text), dbl, flt);
	}

	return 0;
}
