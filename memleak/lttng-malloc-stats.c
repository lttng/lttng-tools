/*
 * lttng-malloc-stats.c
 *
 * LTTng malloc stats printer
 *
 * Copyright (c) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#include <malloc.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>

#define STAT_SIGNAL	SIGUSR2

/* Signal handler */
static void sighandler(int signo, siginfo_t *siginfo, void *context)
{
	malloc_stats();
}

static __attribute__((constructor))
void print_stats_init(void)
{
	/* Attach signal handler on STAT_SIGNAL */
	struct sigaction act;
	int ret;

	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset(&act.sa_mask);
	ret = sigaction(STAT_SIGNAL, &act, NULL);
	assert(!ret);
}
