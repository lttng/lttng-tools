/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_NOTIFICATION_CHANNEL_H
#define LTTNG_NOTIFICATION_CHANNEL_H

#include <lttng/lttng-export.h>

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_notif
@{
*/

struct lttng_endpoint;
struct lttng_condition;
struct lttng_notification;

/*!
@struct lttng_notification_channel

@brief
    Notification channel (opaque type).
*/
struct lttng_notification_channel;

/*!
@brief
    Return type of notification channel API functions.
*/
enum lttng_notification_channel_status {
	/// Success.
	LTTNG_NOTIFICATION_CHANNEL_STATUS_OK = 0,

	/// Notification was dropped/discarded.
	LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED = 1,

	/// Woken up by a signal.
	LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED = 2,

	/// Error.
	LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR = -1,

	/// Connection closed.
	LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED = -2,

	/// Already subscribed.
	LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED = -3,

	/// Unknown \ref api_trigger_cond "trigger condition".
	LTTNG_NOTIFICATION_CHANNEL_STATUS_UNKNOWN_CONDITION = -4,

	/// Unsatisfied precondition.
	LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID = -5,

	/* Unused for the moment */
	LTTNG_NOTIFICATION_CHANNEL_STATUS_UNSUPPORTED_VERSION = -6,
};

/*!
@brief
    Creates a notification channel, connecting to the endpoint
    \lt_p{endpoint}, without any subscription.

@param[in] endpoint
    Endpoint to connect to: must be exactly
    #lttng_session_daemon_notification_endpoint.

@returns
    @parblock
    Notification channel on success, or \c NULL on error.

    Destroy the returned notification channel with
    lttng_notification_channel_destroy().
    @endparblock

@pre
    - @lt_pre_conn
    - \lt_p{endpoint} is #lttng_session_daemon_notification_endpoint.
*/
LTTNG_EXPORT extern struct lttng_notification_channel *
lttng_notification_channel_create(struct lttng_endpoint *endpoint);

/*!
@brief
    Blocks the current thread until the next notification is available
    from the notification channel \lt_p{channel} and sets
    \lt_p{*notification} accordingly.

To avoid blocking when calling this function, check if a notification
is available first with
lttng_notification_channel_has_pending_notification().

@param[in] channel
    Notification channel from which to get the next notification.
@param[out] notification
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*notification}
    to the next notification of \lt_p{channel}.

    Destroy the returned notification with
    lttng_notification_destroy().
    @endparblock

@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED
    One or more notifications were dropped because the client
    couldn't keep up.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED
    The blocking wait was interrupted by a signal.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{notification}

@sa lttng_notification_channel_has_pending_notification() --
    Check whether or not a notification channel has an available
    notification.
*/
LTTNG_EXPORT extern enum lttng_notification_channel_status
lttng_notification_channel_get_next_notification(struct lttng_notification_channel *channel,
						 struct lttng_notification **notification);

/*!
@brief
    Sets \lt_p{*notification_avail} to whether or not the
    notification channel \lt_p{channel}
    has an available notification to get.

Unlike lttng_notification_channel_get_next_notification(), this
function doesn't block the current thread.

@param[in] channel
    Notification channel to check.
@param[out] notification_avail
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*notification_avail} to one of:

    <dl>
      <dt>\c true
      <dd>
	\lt_p{channel} has an available notification.

	Get the available notification with
	lttng_notification_channel_get_next_notification(), which
	won't block the current thread.

      <dt>\c false
      <dd>
	\lt_p{channel} has no available notification.
    </dt>
    @endparblock

@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED
    The connection of the notification channel is closed.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{notification_avail}

@sa lttng_notification_channel_get_next_notification() --
    Get the next available notification from a notification channel.
*/
LTTNG_EXPORT extern enum lttng_notification_channel_status
lttng_notification_channel_has_pending_notification(struct lttng_notification_channel *channel,
						    bool *notification_avail);

/*!
@brief
    Makes the notification channel \lt_p{channel} subscribe to
    the notifications which LTTng sends when a trigger having the
    \ref api_trigger_cond "condition" \lt_p{condition} fires.

When a trigger having a condition exactly equal to \lt_p{condition}
and a \link api_trigger_action_notify “notify”\endlink action fires,
LTTng sends a notification to the notification channel \lt_p{channel}.

Reverse this subscription and stop receiving notifications with
lttng_notification_channel_unsubscribe().

You may only call this function once with a given trigger condition
without first calling lttng_notification_channel_unsubscribe() with it.

@param[in] channel
    Notification channel to which to add a subscription.
@param[in] condition
    Trigger condition which must be satisfied for LTTng to send
    the notifications to subscribe to (not moved).

@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED
    This function was already called with \lt_p{channel} and
    \lt_p{condition} without
    first calling lttng_notification_channel_unsubscribe() (double
    subscription).
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{condition}

@sa lttng_notification_channel_unsubscribe() --
    Make a notification channel unsubscribe from the notifications which
    LTTng sends when a trigger having some condition fires.
*/
LTTNG_EXPORT extern enum lttng_notification_channel_status
lttng_notification_channel_subscribe(struct lttng_notification_channel *channel,
				     const struct lttng_condition *condition);

/*!
@brief
    Makes the notification channel \lt_p{channel} unsubscribe from
    the notifications which LTTng sends when a trigger having the
    \ref api_trigger_cond "condition" \lt_p{condition} fires.

You may only call this function if you already called
lttng_notification_channel_subscribe() with the same parameters.

@param[in] channel
    Notification channel from which to remove a subscription.
@param[in] condition
    Trigger condition which must be satisfied for LTTng to send
    the notifications to unsubscribe from (not moved).

@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_UNKNOWN_CONDITION
    lttng_notification_channel_subscribe() wasn't called with
    the same parameters first (no subscription).
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_NOTIFICATION_CHANNEL_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{condition}

@sa lttng_notification_channel_subscribe() --
    Make a notification channel subscribe to the notifications which
    LTTng sends when a trigger having some condition fires.
*/
LTTNG_EXPORT extern enum lttng_notification_channel_status
lttng_notification_channel_unsubscribe(struct lttng_notification_channel *channel,
				       const struct lttng_condition *condition);

/*!
@brief
    Destroys the notification channel \lt_p{channel}.

@param[in] channel
    @parblock
    Notification channel to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void
lttng_notification_channel_destroy(struct lttng_notification_channel *channel);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_NOTIFICATION_CHANNEL_H */
