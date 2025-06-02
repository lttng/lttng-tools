/*
 * SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_SNAPSHOT_SESSION_H
#define LTTNG_ACTION_SNAPSHOT_SESSION_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_action;
struct lttng_snapshot_output;
struct lttng_rate_policy;

/*!
@addtogroup api_trigger_action_snapshot
@{
*/

/*!
@brief
    Creates an initial “take recording session snapshot” trigger action.

On success, the returned trigger action isn't valid yet; you must
set a target \lt_obj_session name with
lttng_action_snapshot_session_set_session_name().

The initial recording session snapshot output of the returned trigger
action is the default snapshot output of the target recording session.
Set a new snapshot output with
lttng_action_snapshot_session_set_output().

The initial \ref api_trigger_action_rate_policy "rate policy" of the
returned trigger action is
\link api-trigger-action-rate-policy-every-n “every time”\endlink. Set
a new rate policy with lttng_action_snapshot_session_set_rate_policy().

@returns
    @parblock
    Trigger action with the type
    #LTTNG_ACTION_TYPE_SNAPSHOT_SESSION on success,
    or \c NULL on error.

    Destroy the returned trigger action with
    lttng_action_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_action *lttng_action_snapshot_session_create(void);

/*!
@brief
    Sets the target \lt_obj_session name (of which to take a snapshot)
    of the “take recording session snapshot” trigger action
    \lt_p{action} to \lt_p{session_name}.

@param[in] action
    “Take recording session snapshot” trigger
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
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_SNAPSHOT_SESSION}
    @lt_pre_not_null{session_name}

@sa lttng_action_snapshot_session_get_session_name() --
    Get the target recording session name of a
    “take recording session snapshot” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_set_session_name(struct lttng_action *action,
					       const char *session_name);

/*!
@brief
    Sets \lt_p{*session_name} to the target \lt_obj_session name of the
    “take recording session snapshot” trigger action \lt_p{action}.

@param[in] action
    “Take recording session snapshot” trigger
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
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_SNAPSHOT_SESSION}
    @lt_pre_not_null{session_name}

@sa lttng_action_snapshot_session_set_session_name() --
    Set the target recording session name of a
    “take recording session snapshot” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_get_session_name(const struct lttng_action *action,
					       const char **session_name);

/*!
@brief
    Sets the recording session snapshot output
    of the “take recording session snapshot” trigger action
    \lt_p{action} to \lt_p{output}.

@param[in] action
    “Take recording session snapshot” trigger
    action of which to set the snapshot output.
@param[in] output
    Recording session snapshot output of \lt_p{action} (moved).

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_ACTION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_SNAPSHOT_SESSION}
    @lt_pre_not_null{output}
    - \lt_p{output} is a
      \ref api-session-snapshot-output "valid recording session snapshot output".

@sa lttng_action_snapshot_session_get_output() --
    Get the recording session snapshot output of a
    “take recording session snapshot” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_set_output(struct lttng_action *action,
					 struct lttng_snapshot_output *output);

/*!
@brief
    Sets \lt_p{*output} to the recording session snapshot output of the
    “take recording session snapshot” trigger action \lt_p{action}.

@param[in] action
    “Take recording session snapshot” trigger
    action of which to get the recording session snapshot output.
@param[out] output
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*output}
    to the recording session snapshot output of \lt_p{action}.

    \lt_p{action} owns \lt_p{*output}.

    \lt_p{*output} remains valid until the next
    function call with \lt_p{action}.
    @endparblock

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_SNAPSHOT_SESSION}
    @lt_pre_not_null{output}

@sa lttng_action_snapshot_session_set_output() --
    Set the recording session snapshot output of a
    “take recording session snapshot” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_get_output(const struct lttng_action *action,
					 const struct lttng_snapshot_output **output);

/*!
@brief
    Sets the \ref api_trigger_action_rate_policy "rate policy" of the
    “take recording session snapshot” trigger action
    \lt_p{action} to \lt_p{policy}.

@param[in] action
    “Take recording session snapshot” trigger
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
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_SNAPSHOT_SESSION}
    @lt_pre_not_null{policy}

@sa lttng_action_snapshot_session_get_rate_policy() --
    Get the rate policy of a
    “take recording session snapshot” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_set_rate_policy(struct lttng_action *action,
					      const struct lttng_rate_policy *policy);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api_trigger_action_rate_policy "rate policy" of the
    “take recording session snapshot” trigger action \lt_p{action}.

@param[in] action
    “Take recording session snapshot” trigger
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
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_SNAPSHOT_SESSION}
    @lt_pre_not_null{policy}

@sa lttng_action_snapshot_session_set_rate_policy() --
    Set the rate policy of a
    “take recording session snapshot” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_get_rate_policy(const struct lttng_action *action,
					      const struct lttng_rate_policy **policy);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_SNAPSHOT_SESSION_H */
