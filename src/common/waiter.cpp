/*
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "waiter.hpp"
#include <urcu/uatomic.h>
#include <urcu/futex.h>
#include "error.hpp"
#include <poll.h>

/*
 * Number of busy-loop attempts before waiting on futex.
 */
#define WAIT_ATTEMPTS 1000

enum waiter_state {
	/* WAITER_WAITING is compared directly (futex compares it). */
	WAITER_WAITING =	0,
	/* non-zero are used as masks. */
	WAITER_WOKEN_UP =	(1 << 0),
	WAITER_RUNNING =	(1 << 1),
	WAITER_TEARDOWN =	(1 << 2),
};

void lttng_waiter_init(struct lttng_waiter *waiter)
{
	cds_wfs_node_init(&waiter->wait_queue_node);
	uatomic_set(&waiter->state, WAITER_WAITING);
	cmm_smp_mb();
}

/*
 * User must init "waiter" before passing its memory to waker thread.
 */
void lttng_waiter_wait(struct lttng_waiter *waiter)
{
	unsigned int i;

	DBG("Beginning of waiter wait period");
	/* Load and test condition before read state */
	cmm_smp_rmb();
	for (i = 0; i < WAIT_ATTEMPTS; i++) {
		if (uatomic_read(&waiter->state) != WAITER_WAITING) {
			goto skip_futex_wait;
		}
		caa_cpu_relax();
	}
	while (uatomic_read(&waiter->state) == WAITER_WAITING) {
		if (!futex_noasync(&waiter->state, FUTEX_WAIT, WAITER_WAITING, NULL, NULL, 0)) {
			/*
			 * Prior queued wakeups queued by unrelated code
			 * using the same address can cause futex wait to
			 * return 0 even through the futex value is still
			 * WAITER_WAITING (spurious wakeups). Check
			 * the value again in user-space to validate
			 * whether it really differs from WAITER_WAITING.
			 */
			continue;
		}
		switch (errno) {
		case EAGAIN:
			/* Value already changed. */
			goto skip_futex_wait;
		case EINTR:
			/* Retry if interrupted by signal. */
			break;	/* Get out of switch. Check again. */
		default:
			/* Unexpected error. */
			PERROR("futex_noasync");
			abort();
		}
	}
skip_futex_wait:

	/* Tell waker thread than we are running. */
	uatomic_or(&waiter->state, WAITER_RUNNING);

	/*
	 * Wait until waker thread lets us know it's ok to tear down
	 * memory allocated for struct lttng_waiter.
	 */
	for (i = 0; i < WAIT_ATTEMPTS; i++) {
		if (uatomic_read(&waiter->state) & WAITER_TEARDOWN) {
			break;
		}
		caa_cpu_relax();
	}
	while (!(uatomic_read(&waiter->state) & WAITER_TEARDOWN)) {
		poll(NULL, 0, 10);
	}
	LTTNG_ASSERT(uatomic_read(&waiter->state) & WAITER_TEARDOWN);
	DBG("End of waiter wait period");
}

/*
 * Note: lttng_waiter_wake needs waiter to stay allocated throughout its
 * execution. In this scheme, the waiter owns the node memory, and we only allow
 * it to free this memory when it sees the WAITER_TEARDOWN flag.
 */
void lttng_waiter_wake_up(struct lttng_waiter *waiter)
{
	cmm_smp_mb();
	LTTNG_ASSERT(uatomic_read(&waiter->state) == WAITER_WAITING);
	uatomic_set(&waiter->state, WAITER_WOKEN_UP);
	if (!(uatomic_read(&waiter->state) & WAITER_RUNNING)) {
		if (futex_noasync(&waiter->state, FUTEX_WAKE, 1,
				NULL, NULL, 0) < 0) {
			PERROR("futex_noasync");
			abort();
		}
	}
	/* Allow teardown of struct urcu_wait memory. */
	uatomic_or(&waiter->state, WAITER_TEARDOWN);
}
