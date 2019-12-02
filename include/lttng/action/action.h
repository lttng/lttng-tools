/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_H
#define LTTNG_ACTION_H

struct lttng_action;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_action_type {
	LTTNG_ACTION_TYPE_UNKNOWN = -1,
	LTTNG_ACTION_TYPE_NOTIFY = 0,
	LTTNG_ACTION_TYPE_START_SESSION = 1,
	LTTNG_ACTION_TYPE_STOP_SESSION = 2,
	LTTNG_ACTION_TYPE_ROTATE_SESSION = 3,
};

enum lttng_action_status {
	LTTNG_ACTION_STATUS_OK = 0,
	LTTNG_ACTION_STATUS_ERROR = -1,
	LTTNG_ACTION_STATUS_UNKNOWN = -2,
	LTTNG_ACTION_STATUS_INVALID = -3,
	LTTNG_ACTION_STATUS_UNSET = -4,
};

/*
 * Get the type of an action.
 *
 * Returns the type of an action on success, LTTNG_ACTION_TYPE_UNKNOWN on error.
 */
extern enum lttng_action_type lttng_action_get_type(
		struct lttng_action *action);

/*
 * Destroy (frees) an action object.
 */
extern void lttng_action_destroy(struct lttng_action *action);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_H */
