/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_NOTIFY_H
#define LTTNG_ACTION_NOTIFY_H

#include <lttng/lttng-export.h>

struct lttng_action;
struct lttng_rate_policy;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated notification action object.
 *
 * A "notify" action will emit a notification to all clients which have an
 * open notification channel. In order to receive this notification, clients
 * must have subscribed to a condition equivalent to the one paired to this
 * notify action in a trigger.
 *
 * The default rate policy for a notify action is a "every 1" rate policy.
 *
 * Returns a new action on success, NULL on failure. This action must be
 * destroyed using lttng_action_destroy().
 */
LTTNG_EXPORT extern struct lttng_action *lttng_action_notify_create(void);

/*
 * Set the rate policy of a notify action.
 *
 * Returns LTTNG_ACTION_STATUS_OK on success,
 * LTTNG_ACTION_STATUS_ERROR on internal error,
 * LTTNG_ACTION_STATUS_INVALID if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_notify_set_rate_policy(struct lttng_action *action,
				    const struct lttng_rate_policy *policy);

/*
 * Get the rate policy of a notify action.
 *
 * Returns LTTNG_ACTION_STATUS_OK on success,
 * LTTNG_ACTION_STATUS_INVALID if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_notify_get_rate_policy(const struct lttng_action *action,
				    const struct lttng_rate_policy **policy);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_NOTIFY_H */
