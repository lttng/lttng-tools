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

#ifndef LTTNG_NOTIFICATION_CHANNEL_H
#define LTTNG_NOTIFICATION_CHANNEL_H

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_endpoint;
struct lttng_condition;
struct lttng_notification;
struct lttng_notification_channel;

/* LTTng Notification channel */
enum lttng_notification_channel_status {
	LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED = 1,
	LTTNG_NOTIFICATION_CHANNEL_STATUS_OK = 0,
	LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR = -1,
	LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED = -2,
	LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED = -3,
	/* Condition unknown. */
	LTTNG_NOTIFICATION_CHANNEL_STATUS_UNKNOWN_CONDITION = -4,
	LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID = -5,
	LTTNG_NOTIFICATION_CHANNEL_STATUS_UNSUPPORTED_VERSION = -6,
};

extern struct lttng_notification_channel *lttng_notification_channel_create(
		struct lttng_endpoint *endpoint);

extern enum lttng_notification_channel_status
lttng_notification_channel_get_next_notification(
		struct lttng_notification_channel *channel,
		struct lttng_notification **notification);

extern enum lttng_notification_channel_status
lttng_notification_channel_subscribe(
		struct lttng_notification_channel *channel,
		const struct lttng_condition *condition);

extern enum lttng_notification_channel_status
lttng_notification_channel_unsubscribe(
		struct lttng_notification_channel *channel,
		const struct lttng_condition *condition);

extern void lttng_notification_channel_destroy(
		struct lttng_notification_channel *channel);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_NOTIFICATION_CHANNEL_H */
