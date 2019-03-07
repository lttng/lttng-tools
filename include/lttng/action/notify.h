/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_NOTIFY_H
#define LTTNG_ACTION_NOTIFY_H

struct lttng_action;

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
 * Returns a new action on success, NULL on failure. This action must be
 * destroyed using lttng_action_destroy().
 */
extern struct lttng_action *lttng_action_notify_create(void);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_NOTIFY_H */
