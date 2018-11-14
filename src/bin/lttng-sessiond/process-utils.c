/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
