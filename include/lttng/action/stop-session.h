/*
 * SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_STOP_SESSION_H
#define LTTNG_ACTION_STOP_SESSION_H

#include <lttng/lttng-export.h>

struct lttng_action;
struct lttng_rate_policy;

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_action_stop_session
@{
*/

/*!
@brief
    Creates an initial “stop recording session” trigger action.

On success, the returned trigger action isn't valid yet; you must
set a target \lt_obj_session name with
lttng_action_stop_session_set_session_name().

The initial \ref api_trigger_action_rate_policy "rate policy" of the
returned trigger action is
\link api-trigger-action-rate-policy-every-n “every time”\endlink.
Set a new rate policy with
lttng_action_stop_session_set_rate_policy().

@returns
    @parblock
    Trigger action with the type
    #LTTNG_ACTION_TYPE_STOP_SESSION on success,
    or \c NULL on error.

    Destroy the returned trigger action with
    lttng_action_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_action *lttng_action_stop_session_create(void);

/*!
@brief
    Sets the target \lt_obj_session name (to stop) of the
    “stop recording session” trigger action
    \lt_p{action} to \lt_p{session_name}.

@param[in] action
    “Stop recording session” trigger
    action of which to set the target recording session name.
@param[in] session_name
    Target recording session name of \lt_p{action} (copied).

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_ACTION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_STOP_SESSION}
    @lt_pre_not_null{session_name}

@sa lttng_action_stop_session_get_session_name() --
    Get the target recording session name of a
    “stop recording session” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_stop_session_set_session_name(struct lttng_action *action, const char *session_name);

/*!
@brief
    Sets \lt_p{*session_name} to the target \lt_obj_session name of the
    “stop recording session” trigger action \lt_p{action}.

@param[in] action
    “Stop recording session” trigger
    action of which to get the target recording session name.
@param[out] session_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*session_name}
    to the target recording session name of \lt_p{action}.

    \lt_p{action} owns \lt_p{*session_name}.

    \lt_p{*session_name} remains valid until the next
    function call with \lt_p{action}.
    @endparblock

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_STOP_SESSION}
    @lt_pre_not_null{session_name}

@sa lttng_action_stop_session_set_session_name() --
    Set the target recording session name of a
    “stop recording session” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_stop_session_get_session_name(const struct lttng_action *action,
					   const char **session_name);

/*!
@brief
    Sets the \ref api_trigger_action_rate_policy "rate policy" of the
    “stop recording session” trigger action
    \lt_p{action} to \lt_p{policy}.

@param[in] action
    “Stop recording session” trigger
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
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_STOP_SESSION}
    @lt_pre_not_null{policy}

@sa lttng_action_stop_session_get_rate_policy() --
    Get the rate policy of a
    “stop recording session” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_stop_session_set_rate_policy(struct lttng_action *action,
					  const struct lttng_rate_policy *policy);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api_trigger_action_rate_policy "rate policy" of the
    “stop recording session” trigger action \lt_p{action}.

@param[in] action
    “Stop recording session” trigger
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
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_STOP_SESSION}
    @lt_pre_not_null{policy}

@sa lttng_action_stop_session_set_rate_policy() --
    Set the rate policy of a
    “stop recording session” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_stop_session_get_rate_policy(const struct lttng_action *action,
					  const struct lttng_rate_policy **policy);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_STOP_SESSION_H */
