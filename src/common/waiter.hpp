/*
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * This code is originally adapted from userspace-rcu's urcu-wait.h
 */

#ifndef LTTNG_WAITER_H
#define LTTNG_WAITER_H

#define _LGPL_SOURCE

#include "macros.hpp"

#include <stdbool.h>
#include <stdint.h>
#include <urcu/wfstack.h>

struct lttng_waiter {
	struct cds_wfs_node wait_queue_node;
	int32_t state;
};

void lttng_waiter_init(struct lttng_waiter *waiter);

void lttng_waiter_wait(struct lttng_waiter *waiter);

/*
 * lttng_waiter_wake_up must only be called by a single waker.
 * It is invalid for multiple "wake" operations to be invoked
 * on a single waiter without re-initializing it before.
 */
void lttng_waiter_wake_up(struct lttng_waiter *waiter);

#endif /* LTTNG_WAITER_H */
