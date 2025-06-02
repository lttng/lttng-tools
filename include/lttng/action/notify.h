/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

/*!
@addtogroup api_trigger_action_notify
@{
*/

/*!
@brief
    Creates a “notify” trigger action.

The initial \ref api_trigger_action_rate_policy "rate policy" of the
returned trigger action is
\link api-trigger-action-rate-policy-every-n “every time”\endlink. Set
a new rate policy with lttng_action_notify_set_rate_policy().

@returns
    @parblock
    Trigger action with the type
    #LTTNG_ACTION_TYPE_NOTIFY on success,
    or \c NULL on error.

    Destroy the returned trigger action with
    lttng_action_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_action *lttng_action_notify_create(void);

/*!
@brief
    Sets the \ref api_trigger_action_rate_policy "rate policy" of the
    “notify” trigger action \lt_p{action} to \lt_p{policy}.

@param[in] action
    “Notify” trigger
    action of which to set the rate policy.
@param[in] policy
    Rate policy of \lt_p{action} (copied).

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_ACTION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_NOTIFY}
    @lt_pre_not_null{policy}

@sa lttng_action_notify_get_rate_policy() --
    Get the rate policy of a “notify” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_notify_set_rate_policy(struct lttng_action *action,
				    const struct lttng_rate_policy *policy);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api_trigger_action_rate_policy "rate policy" of the
    “notify” trigger action \lt_p{action}.

@param[in] action
    “Notify” trigger
    action of which to get the rate policy.
@param[out] policy
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*policy}
    to the rate policy of \lt_p{action}.

    \lt_p{action} owns \lt_p{*policy}.

    \lt_p{*policy} remains valid until the next
    function call with \lt_p{action}.
    @endparblock

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_NOTIFY}
    @lt_pre_not_null{policy}

@sa lttng_action_notify_set_rate_policy() --
    Set the rate policy of a “notify” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_notify_get_rate_policy(const struct lttng_action *action,
				    const struct lttng_rate_policy **policy);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_NOTIFY_H */
