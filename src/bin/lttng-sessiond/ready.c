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

#include <common/macros.h>
#include <urcu.h>
#include "lttng-sessiond.h"

/*
 * The initialization of the session daemon is done in multiple phases.
 *
 * While all threads are launched near-simultaneously, only some of them
 * are needed to ensure the session daemon can start to respond to client
 * requests.
 *
 * There are two important guarantees that we wish to offer with respect
 * to the initialisation of the session daemon:
 *   - When the daemonize/background launcher process exits, the sessiond
 *     is fully able to respond to client requests,
 *   - Auto-loaded sessions are visible to clients.
 *
 * In order to achieve this, a number of support threads have to be launched
 * to allow the "client" thread to function properly. Moreover, since the
 * "load session" thread needs the client thread, we must provide a way
 * for the "load session" thread to know that the "client" thread is up
 * and running.
 *
 * Hence, the support threads decrement the lttng_sessiond_ready counter
 * while the "client" threads waits for it to reach 0. Once the "client" thread
 * unblocks, it posts the message_thread_ready semaphore which allows the
 * "load session" thread to progress.
 *
 * This implies that the "load session" thread is the last to be initialized
 * and will explicitly call sessiond_signal_parents(), which signals the parents
 * that the session daemon is fully initialized.
 *
 * The four (4) support threads are:
 *  - agent_thread
 *  - notification_thread
 *  - rotation_thread
 *  - health_thread
 */
#define NR_LTTNG_SESSIOND_SUPPORT_THREADS 4
int lttng_sessiond_ready = NR_LTTNG_SESSIOND_SUPPORT_THREADS;

LTTNG_HIDDEN
void sessiond_notify_ready(void)
{
	/*
	 * This memory barrier is paired with the one performed by
	 * the client thread after it has seen that 'lttng_sessiond_ready' is 0.
	 *
	 * The purpose of these memory barriers is to ensure that all
	 * initialization operations of the various threads that call this
	 * function to signal that they are ready are commited/published
	 * before the client thread can see the 'lttng_sessiond_ready' counter
	 * reach 0.
	 *
	 * Note that this could be a 'write' memory barrier, but a full barrier
	 * is used in case the code using this utility changes. The performance
	 * implications of this choice are minimal since this is a slow path.
	 */
	cmm_smp_mb();
	uatomic_sub(&lttng_sessiond_ready, 1);
}
