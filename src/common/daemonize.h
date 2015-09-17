#ifndef LTTNG_DAEMONIZE_H
#define LTTNG_DAEMONIZE_H

/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2014 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unistd.h>
#include <common/macros.h>

/*
 * Daemonize this process by forking and making the parent wait for the child
 * to signal it indicating readiness. Once received, the parent successfully
 * quits.
 *
 * The child process undergoes the same action that daemon(3) does meaning
 * setsid, chdir, and dup /dev/null into 0, 1 and 2.
 *
 * Return 0 on success else -1 on error.
 */
LTTNG_HIDDEN
int lttng_daemonize(pid_t *child_ppid, int *completion_flag,
		int close_fds);

#endif /* LTTNG_DAEMONIZE_H */
