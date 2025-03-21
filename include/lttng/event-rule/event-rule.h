/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_H
#define LTTNG_EVENT_RULE_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_event_rule;

enum lttng_event_rule_type {
	LTTNG_EVENT_RULE_TYPE_UNKNOWN = -1,
	LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL = 0,
	LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE = 1,
	LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT = 2,
	LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE = 3,
	LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT = 4,
	LTTNG_EVENT_RULE_TYPE_JUL_LOGGING = 5,
	LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING = 6,
	LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING = 7,
	LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING = 8,
};

enum lttng_event_rule_status {
	LTTNG_EVENT_RULE_STATUS_OK = 0,
	LTTNG_EVENT_RULE_STATUS_ERROR = -1,
	LTTNG_EVENT_RULE_STATUS_UNKNOWN = -2,
	LTTNG_EVENT_RULE_STATUS_INVALID = -3,
	LTTNG_EVENT_RULE_STATUS_UNSET = -4,
	LTTNG_EVENT_RULE_STATUS_UNSUPPORTED = -5,
};

/**
 * An event rule describes a set of criteria to be used as a discriminant in
 * regards to a set of events.
 */

/*
 * Get the event rule type.
 *
 * Returns the type of an event rule on success, LTTNG_EVENT_RULE_UNKNOWN on
 * error.
 */
LTTNG_EXPORT extern enum lttng_event_rule_type
lttng_event_rule_get_type(const struct lttng_event_rule *event_rule);

/*
 * Destroy an event rule object.
 */
LTTNG_EXPORT extern void lttng_event_rule_destroy(struct lttng_event_rule *rule);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_H */
