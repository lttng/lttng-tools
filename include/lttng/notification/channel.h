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

/**
 * A notification channel is used to receive notifications from various
 * LTTng components.
 *
 * Notification channels connect a client to an LTTng endpoint
 * (see lttng/endpoint.h) and allows client to subscribe and unsubscribe
 * to various types of notifications which are associated to conditions.
 *
 * In order to emit a notification, a condition must be associated to a
 * notify action within a trigger. A client wishing to consume such
 * conditions must explicitly subscribe to them by using an equivalent
 * condition.
 */

/*
 * Create a notification channel connected to a given endpoint.
 *
 * The only supported endpoint, at the moment, is the
 * lttng_session_daemon_notification_endpoint, which is a singleton
 * declared in the lttng/endpoint.h header.
 *
 * Returns an lttng_notification_channel on success, NULL on failure.
 * The returned lttng_notification_channel must be destroyed using
 * the lttng_notification_channel_destroy() function.
 */
extern struct lttng_notification_channel *lttng_notification_channel_create(
		struct lttng_endpoint *endpoint);

/*
 * Get the next notification received on a notification channel.
 *
 * This call will block until a notification is received on the notification
 * channel or until the endpoint closes the connection.
 *
 * The returned notification's ownership is transferred to the caller and
 * it must be destroyed using lttng_notification_destroy().
 *
 * Notifications can be dropped if a client consumes the notifications sent
 * through the notification channel too slowly.
 *
 * Returns LTTNG_NOTIFICATION_CHANNEL_STATUS_OK and a notificationon success,
 * LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID if an invalid parameter was
 * provided, or LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED if
 * notifications were dropped.
 */
extern enum lttng_notification_channel_status
lttng_notification_channel_get_next_notification(
		struct lttng_notification_channel *channel,
		struct lttng_notification **notification);

/*
 * Subscribe to notifications of a condition through a notification channel.
 *
 * The caller retains the ownership of the condition passed through this call
 * and it can be disposed-of at any moment after this call.
 *
 * An error will be reported if the client tries to subscribe to the same
 * condition multiple times without unsubscribing.
 *
 * Returns LTTNG_NOTIFICATION_CHANNEL_STATUS_OK on success,
 * LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID if an invalid parameter was
 * provided, or LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED if the
 * client was already subscribed to the condition through this channel.
 */
extern enum lttng_notification_channel_status
lttng_notification_channel_subscribe(
		struct lttng_notification_channel *channel,
		const struct lttng_condition *condition);

/*
 * Unsubscribe to notifications of a condition through a notification channel.
 *
 * The caller retains the ownership of the condition passed through this call
 * and it can be disposed-of at any moment after this call.
 *
 * An error will be reported if the client tries to unsubscribe to from a
 * conditions' notifications to which it was not previously subscribed.
 *
 * Returns LTTNG_NOTIFICATION_CHANNEL_STATUS_OK on success,
 * LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID if an invalid parameter was
 * provided, or LTTNG_NOTIFICATION_CHANNEL_STATUS_UNKNOWN_CONDITION if the
 * client was not already subscribed to the condition through this channel.
 */
extern enum lttng_notification_channel_status
lttng_notification_channel_unsubscribe(
		struct lttng_notification_channel *channel,
		const struct lttng_condition *condition);

/*
 * Closes and destroys (frees) a notification channel.
 */
extern void lttng_notification_channel_destroy(
		struct lttng_notification_channel *channel);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_NOTIFICATION_CHANNEL_H */
