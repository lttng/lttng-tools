/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_H
#define LTTNG_CONDITION_H

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_condition;

enum lttng_condition_type {
	LTTNG_CONDITION_TYPE_UNKNOWN = -1,
	LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE = 100,
	LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH = 101,
	LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW = 102,
	LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING = 103,
	LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED = 104,
	LTTNG_CONDITION_TYPE_EVENT_RULE_HIT = 105,
};

enum lttng_condition_status {
	LTTNG_CONDITION_STATUS_OK = 0,
	LTTNG_CONDITION_STATUS_ERROR = -1,
	LTTNG_CONDITION_STATUS_UNKNOWN = -2,
	LTTNG_CONDITION_STATUS_INVALID = -3,
	LTTNG_CONDITION_STATUS_UNSET = -4,
};

/*
 * Get the type of a condition.
 *
 * Returns the type of a condition on success, LTTNG_CONDITION_TYPE_UNKNOWN on
 * error.
 */
extern enum lttng_condition_type lttng_condition_get_type(
		const struct lttng_condition *condition);

/*
 * Destroy (release) a condition object.
 */
extern void lttng_condition_destroy(struct lttng_condition *condition);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_H */
