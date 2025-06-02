/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_NOTIFICATION_H
#define LTTNG_NOTIFICATION_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_notif
@{
*/

struct lttng_condition;
struct lttng_evaluation;

/*!
@struct lttng_notification

@brief
    Notification (opaque type).
*/
struct lttng_notification;

/*!
@brief
    Returns the \ref api_trigger_cond "condition" which caused a trigger
    to send the notification \lt_p{notification}.

@param[in] notification
    Notification of which to get the satisfied trigger condition.

@returns
    @parblock
    Satisfied trigger condition which caused a trigger to send
    \lt_p{notification}, or \c NULL on error.

    \lt_p{notification} owns the returned trigger condition.

    The returned trigger condition remains valid as long
    as \lt_p{notification} exists.
    @endparblock

@pre
    @lt_pre_not_null{notification}
*/
LTTNG_EXPORT extern const struct lttng_condition *
lttng_notification_get_condition(struct lttng_notification *notification);

/*!
@brief
    Returns the \ref api-trigger-cond-eval "evaluation" of the
    \ref api_trigger_cond "condition" which
    caused a trigger to send the notification \lt_p{notification}.

A trigger condition evaluation contains values which LTTng captured
when the trigger fired.

@param[in] notification
    Notification of which to get the evaluation of the
    satisfied trigger condition.

@returns
    @parblock
    Evaluation of the satisfied trigger condition which caused a trigger
    to send \lt_p{notification}, or \c NULL on error.

    \lt_p{notification} owns the returned trigger condition evaluation.

    The returned trigger condition evaluation remains valid as long
    as \lt_p{notification} exists.
    @endparblock

@pre
    @lt_pre_not_null{notification}
*/
LTTNG_EXPORT extern const struct lttng_evaluation *
lttng_notification_get_evaluation(struct lttng_notification *notification);

/*
 * Get a notification's origin trigger.
 *
 * The notification retains the ownership of the trigger object. Hence, it is
 * not valid to access that object after the destruction of its associated
 * notification.
 *
 * Returns an lttng_trigger object on success, NULL on error.
 */

/*!
@brief
    Returns the trigger which fired to make LTTng send the
    notification \lt_p{notification}.

@param[in] notification
    Notification of which to get the firing trigger.

@returns
    @parblock
    Trigger which fired, making LTTng send
    \lt_p{notification}, or \c NULL on error.

    \lt_p{notification} owns the returned trigger.

    The returned trigger remains valid as long
    as \lt_p{notification} exists.
    @endparblock

@pre
    @lt_pre_not_null{notification}
*/
LTTNG_EXPORT extern const struct lttng_trigger *
lttng_notification_get_trigger(struct lttng_notification *notification);

/*!
@brief
    Destroys the notification \lt_p{notification}.

@param[in] notification
    @parblock
    Notification to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_notification_destroy(struct lttng_notification *notification);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_NOTIFICATION_H */
