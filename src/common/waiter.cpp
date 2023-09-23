/*
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "error.hpp"
#include "macros.hpp"
#include "waiter.hpp"

#include <poll.h>
#include <urcu/futex.h>
#include <urcu/uatomic.h>

namespace {
/* Number of busy-loop attempts before waiting on futex. */
constexpr auto wait_attempt_count = 1000;

enum waiter_state {
	/* WAITER_WAITING is compared directly (futex compares it). */
	WAITER_WAITING = 0,
	/* non-zero are used as masks. */
	WAITER_WOKEN_UP = (1 << 0),
	WAITER_RUNNING = (1 << 1),
	WAITER_TEARDOWN = (1 << 2),
};
} /* namespace */

lttng::synchro::waiter::waiter()
{
	arm();
}

void lttng::synchro::waiter::arm() noexcept
{
	cds_wfs_node_init(&_wait_queue_node);
	uatomic_set(&_state, WAITER_WAITING);
	cmm_smp_mb();
}

/*
 * User must arm "waiter" before passing its memory to waker thread.
 */
void lttng::synchro::waiter::wait()
{
	DBG("Beginning of waiter \"wait\" period");

	/* Load and test condition before read state. */
	cmm_smp_rmb();
	for (unsigned int i = 0; i < wait_attempt_count; i++) {
		if (uatomic_read(&_state) != WAITER_WAITING) {
			goto skip_futex_wait;
		}

		caa_cpu_relax();
	}

	while (uatomic_read(&_state) == WAITER_WAITING) {
		if (!futex_noasync(
			    &_state, FUTEX_WAIT, WAITER_WAITING, nullptr, nullptr, 0)) {
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
			break; /* Get out of switch. Check again. */
		default:
			/* Unexpected error. */
			PERROR("futex_noasync");
			abort();
		}
	}
skip_futex_wait:

	/* Tell waker thread than we are running. */
	uatomic_or(&_state, WAITER_RUNNING);

	/*
	 * Wait until waker thread lets us know it's ok to tear down
	 * memory allocated for struct lttng_waiter.
	 */
	for (unsigned int i = 0; i < wait_attempt_count; i++) {
		if (uatomic_read(&_state) & WAITER_TEARDOWN) {
			break;
		}

		caa_cpu_relax();
	}

	while (!(uatomic_read(&_state) & WAITER_TEARDOWN)) {
		poll(nullptr, 0, 10);
	}

	LTTNG_ASSERT(uatomic_read(&_state) & WAITER_TEARDOWN);
	DBG("End of waiter \"wait\" period");
}

lttng::synchro::waker lttng::synchro::waiter::get_waker()
{
	return lttng::synchro::waker(_state);
}

/*
 * Note: lttng_waiter_wake needs waiter to stay allocated throughout its
 * execution. In this scheme, the waiter owns the node memory, and we only allow
 * it to free this memory when it sees the WAITER_TEARDOWN flag.
 */
void lttng::synchro::waker::wake()
{
	cmm_smp_mb();

	LTTNG_ASSERT(uatomic_read(&_state) == WAITER_WAITING);

	uatomic_set(&_state, WAITER_WOKEN_UP);
	if (!(uatomic_read(&_state) & WAITER_RUNNING)) {
		if (futex_noasync(&_state, FUTEX_WAKE, 1, nullptr, nullptr, 0) < 0) {
			PERROR("futex_noasync");
			abort();
		}
	}

	/* Allow teardown of struct urcu_wait memory. */
	uatomic_or(&_state, WAITER_TEARDOWN);
}

lttng::synchro::wait_queue::wait_queue()
{
	cds_wfs_init(&_stack);
}

void lttng::synchro::wait_queue::add(waiter &waiter) noexcept
{
	(void) cds_wfs_push(&_stack, &waiter._wait_queue_node);
}

void lttng::synchro::wait_queue::wake_all()
{
	/* Move all waiters from the queue to our local stack. */
	auto *waiters = __cds_wfs_pop_all(&_stack);

	/* Wake all waiters in our stack head. */
	cds_wfs_node *iter, *iter_n;
	cds_wfs_for_each_blocking_safe(waiters, iter, iter_n) {
		auto& waiter = *lttng::utils::container_of(
			iter, &lttng::synchro::waiter::_wait_queue_node);

		/* Don't wake already running threads. */
		if (waiter._state & WAITER_RUNNING) {
			continue;
		}

		waiter.get_waker().wake();
	}
}
