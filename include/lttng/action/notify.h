/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
