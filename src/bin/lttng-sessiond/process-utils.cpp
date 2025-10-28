/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-sessiond.hpp"

#include <signal.h>

/* Notify parents that we are ready for cmd and health check */
void sessiond_signal_parents()
{
	/*
	 * Notify parent pid that we are ready to accept command
	 * for client side.  This ppid is the one from the
	 * external process that spawned us.
	 */
	if (the_config.sig_parent) {
		DBG_FMT("Notifying parent of readiness: pid={}", the_ppid);
		kill(the_ppid, SIGUSR1);
	}

	/*
	 * Notify the parent of the fork() process that we are
	 * ready.
	 */
	if (the_config.daemonize || the_config.background) {
		DBG_FMT("Notifying fork parent of readiness: pid={}", the_child_ppid);
		kill(the_child_ppid, SIGUSR1);
	}
}
