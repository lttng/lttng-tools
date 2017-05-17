/*
 * Copyright (C) 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * This code is originally adapted from userspace-rcu's urcu-wait.h
 */

#ifndef LTTNG_WAITER_H
#define LTTNG_WAITER_H

#define _LGPL_SOURCE

#include <stdint.h>
#include <urcu/wfstack.h>
#include <stdbool.h>
#include "macros.h"

struct lttng_waiter {
	struct cds_wfs_node wait_queue_node;
	int32_t state;
};

LTTNG_HIDDEN
void lttng_waiter_init(struct lttng_waiter *waiter);

LTTNG_HIDDEN
void lttng_waiter_wait(struct lttng_waiter *waiter);

/*
 * lttng_waiter_wake_up must only be called by a single waker.
 * It is invalid for multiple "wake" operations to be invoked
 * on a single waiter without re-initializing it before.
 */
LTTNG_HIDDEN
void lttng_waiter_wake_up(struct lttng_waiter *waiter);

#endif /* LTTNG_WAITER_H */
