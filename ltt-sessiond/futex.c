/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *                       Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/futex.h>

#include <lttngerr.h>

#include "futex.h"

/*
 * This futex wait/wake scheme only works for N wakers / 1 waiters. Hence the
 * "nto1" added to all function signature.
 *
 * Please see wait_gp()/update_counter_and_wait() calls in urcu.c in the urcu
 * git tree for a detail example of this scheme being used. futex_async() is
 * the urcu wrapper over the futex() sycall.
 *
 * There is also a formal verification available in the git tree.
 *
 *   branch: formal-model
 *   commit id: 2a8044f3493046fcc8c67016902dc7beec6f026a
 *
 * Ref: git://git.lttng.org/userspace-rcu.git
 */

/*
 * Prepare futex.
 */
void futex_nto1_prepare(int32_t *futex)
{
	uatomic_set(futex, -1);
	cmm_smp_mb();

	DBG("Futex n to 1 prepare done");
}

/*
 * Wait futex.
 */
void futex_nto1_wait(int32_t *futex)
{
	cmm_smp_mb();

	if (uatomic_read(futex) == -1) {
		futex_async(futex, FUTEX_WAIT, -1, NULL, NULL, 0);
	}

	DBG("Futex n to 1 wait done");
}

/*
 * Wake 1 futex.
 */
void futex_nto1_wake(int32_t *futex)
{
	if (unlikely(uatomic_read(futex) == -1)) {
		uatomic_set(futex, 0);
		futex_async(futex, FUTEX_WAKE, 1, NULL, NULL, 0);
	}

	DBG("Futex n to 1 wake done");
}
