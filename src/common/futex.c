/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *                       Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _LGPL_SOURCE
#include <limits.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/futex.h>

#include <common/common.h>

#include "futex.h"

/*
 * This futex wait/wake scheme only works for N wakers / 1 waiters. Hence the
 * "nto1" added to all function signature.
 *
 * The code is adapted from the adaptative busy wait/wake_up scheme used in
 * liburcu.
 */

/* Number of busy-loop attempts before waiting on futex. */
#define FUTEX_WAIT_ATTEMPTS 1000

enum futex_wait_state {
	/* FUTEX_WAIT_WAITING is compared directly (futex() compares it). */
	FUTEX_WAIT_WAITING =	0,
	/* non-zero are used as masks. */
	FUTEX_WAIT_WAKEUP =	(1 << 0),
	FUTEX_WAIT_RUNNING =	(1 << 1),
	FUTEX_WAIT_TEARDOWN =	(1 << 2),
};

/*
 * Update futex according to active or not. This scheme is used to wake every
 * libust waiting on the shared memory map futex hence the INT_MAX used in the
 * futex() call. If active, we set the value and wake everyone else we indicate
 * that we are gone (cleanup() case).
 */
LTTNG_HIDDEN
void futex_wait_update(int32_t *futex, int active)
{
	if (active) {
		uatomic_set(futex, 1);
		if (futex_async(futex, FUTEX_WAKE,
				INT_MAX, NULL, NULL, 0) < 0) {
			PERROR("futex_async");
			abort();
		}
	} else {
		uatomic_set(futex, 0);
	}

	DBG("Futex wait update active %d", active);
}

/*
 * Prepare futex.
 */
LTTNG_HIDDEN
void futex_nto1_prepare(int32_t *futex)
{
	uatomic_set(futex, FUTEX_WAIT_WAITING);
	cmm_smp_mb();

	DBG("Futex n to 1 prepare done");
}

/*
 * Wait futex.
 */
LTTNG_HIDDEN
void futex_nto1_wait(int32_t *futex)
{
	unsigned int i;

	/* Load and test condition before read state */
	cmm_smp_rmb();
	for (i = 0; i < FUTEX_WAIT_ATTEMPTS; i++) {
		if (uatomic_read(futex) != FUTEX_WAIT_WAITING)
			goto skip_futex_wait;
		caa_cpu_relax();
	}
	while (futex_noasync(futex, FUTEX_WAIT, FUTEX_WAIT_WAITING,
			NULL, NULL, 0)) {
		switch (errno) {
		case EWOULDBLOCK:
			/* Value already changed. */
			goto skip_futex_wait;
		case EINTR:
			/* Retry if interrupted by signal. */
			break;	/* Get out of switch. */
		default:
			/* Unexpected error. */
			PERROR("futex");
			abort();
		}
	}
skip_futex_wait:

	/* Tell waker thread than we are running. */
	uatomic_or(futex, FUTEX_WAIT_RUNNING);

	/*
	 * Wait until waker thread lets us know it's ok to tear down
	 * memory allocated for the futex.
	 */
	for (i = 0; i < FUTEX_WAIT_ATTEMPTS; i++) {
		if (uatomic_read(futex) & FUTEX_WAIT_TEARDOWN)
			break;
		caa_cpu_relax();
	}
	while (!(uatomic_read(futex) & FUTEX_WAIT_TEARDOWN))
		poll(NULL, 0, 10);
	assert(uatomic_read(futex) & FUTEX_WAIT_TEARDOWN);
	DBG("Futex n to 1 wait done");
}

/*
 * Wake 1 futex.
 */
LTTNG_HIDDEN
void futex_nto1_wake(int32_t *futex)
{
	cmm_smp_mb();
	uatomic_set(futex, FUTEX_WAIT_WAKEUP);
	if (!(uatomic_read(futex) & FUTEX_WAIT_RUNNING)) {
		if (futex_noasync(futex, FUTEX_WAKE, 1,
				NULL, NULL, 0) < 0) {
			PERROR("futex_noasync");
			abort();
		}
	}
	/* Allow teardown of futex. */
	uatomic_or(futex, FUTEX_WAIT_TEARDOWN);
	DBG("Futex n to 1 wake done");
}
