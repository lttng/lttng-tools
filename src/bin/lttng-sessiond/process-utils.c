/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <signal.h>
#include "lttng-sessiond.h"

/* Notify parents that we are ready for cmd and health check */
void sessiond_signal_parents(void)
{
	/*
	 * Notify parent pid that we are ready to accept command
	 * for client side.  This ppid is the one from the
	 * external process that spawned us.
	 */
	if (config.sig_parent) {
		kill(ppid, SIGUSR1);
	}

	/*
	 * Notify the parent of the fork() process that we are
	 * ready.
	 */
	if (config.daemonize || config.background) {
		kill(child_ppid, SIGUSR1);
	}
}
