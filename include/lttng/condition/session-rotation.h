/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_SESSION_ROTATION_H
#define LTTNG_CONDITION_SESSION_ROTATION_H

#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/domain.h>
#include <lttng/location.h>
#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_cond_rotation
@{
*/

/*!
@brief
    Creates an initial “recording session rotation starts”
    trigger condition to execute
    an action when the \ref api_session_rotation "rotation"
    operation of a given \lt_obj_session starts.

On success, the returned trigger condition isn't valid yet; you must
set a target \lt_obj_session name with
lttng_condition_session_rotation_set_session_name().

@returns
    @parblock
    Trigger condition with the type
    #LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING on success,
    or \c NULL on error.

    Destroy the returned trigger condition with
    lttng_condition_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_condition *lttng_condition_session_rotation_ongoing_create(void);

/*!
@brief
    Creates an initial “recording session rotation finishes”
    trigger condition to execute
    an action when the \ref api_session_rotation "rotation" operation
    of a given \lt_obj_session finishes.

On success, the returned trigger condition isn't valid yet; you must
set a target \lt_obj_session name with
lttng_condition_session_rotation_set_session_name().

@returns
    @parblock
    Trigger condition with the type
    #LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED on success,
    or \c NULL on error.

    Destroy the returned trigger condition with
    lttng_condition_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_condition *lttng_condition_session_rotation_completed_create(void);

/*!
@brief
    Sets \lt_p{*session_name} to the target \lt_obj_session name of the
    “recording session rotation starts/finishes” trigger
    condition \lt_p{condition}.

@param[in] condition
    “Recording session rotation starts/finishes” trigger
    condition of which to get the target recording session name.
@param[out] session_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*session_name}
    to the target recording session name of \lt_p{condition}.

    \lt_p{condition} owns \lt_p{*session_name}.

    \lt_p{*session_name} remains valid until the next
    function call with \lt_p{condition}.
    @endparblock

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_UNSET
    \lt_p{condition} has no target recording session name.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING or
      #LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED.
    @lt_pre_not_null{session_name}

@sa lttng_condition_session_rotation_set_session_name() --
    Set the target recording session name of a
    “recording session rotation starts/finishes”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_session_rotation_get_session_name(const struct lttng_condition *condition,
						  const char **session_name);

/*!
@brief
    Sets the target \lt_obj_session name of the
    “recording session rotation starts/finishes”
    trigger condition \lt_p{condition} to \lt_p{session_name}.

@param[in] condition
    “Recording session rotation starts/finishes” trigger
    condition of which to set the target recording session name.
@param[in] session_name
    Target recording session name of \lt_p{condition} (copied).

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING or
      #LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED.
    @lt_pre_not_null{session_name}

@sa lttng_condition_session_rotation_get_session_name() --
    Get the target recording session name of a
    “recording session rotation starts/finishes”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_session_rotation_set_session_name(struct lttng_condition *condition,
						  const char *session_name);

/*!
@brief
    Sets \lt_p{*id} to the \lt_obj_session
    \ref api_session_rotation "rotation" ID of the
    “recording session rotation starts/finishes” trigger
    condition evaluation \lt_p{evaluation}.

@param[in] evaluation
    “Recording session rotation starts/finishes” trigger
    condition evaluation of which to get the captured recording
    session rotation ID.
@param[out] id
    <strong>On success</strong>, this function sets
    \lt_p{*id} to the captured recording session rotation ID
    of \lt_p{evaluation}.

@retval #LTTNG_EVALUATION_STATUS_OK
    Success.
@retval #LTTNG_EVALUATION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{evaluation}
    - \lt_p{evaluation} has the type
      #LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING or
      #LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED.
    @lt_pre_not_null{id}
*/
LTTNG_EXPORT extern enum lttng_evaluation_status
lttng_evaluation_session_rotation_get_id(const struct lttng_evaluation *evaluation, uint64_t *id);

/*!
@brief
    Sets \lt_p{*location} to the captured resulting
    \ref api_session_trace_archive_loc "trace chunk archive location"
    of the
    “recording session rotation finishes” trigger
    condition evaluation \lt_p{evaluation}.

@param[in] evaluation
    “Recording session rotation finishes” trigger
    condition evaluation of which to get the captured
    resulting trace chunk archive location.
@param[out] location
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*location} to the captured resulting trace chunk
    archive location of \lt_p{evaluation}.

    This function may also set \lt_p{*location} to \c NULL if
    the trace chunk archive location has expired.
    @endparblock

@retval #LTTNG_EVALUATION_STATUS_OK
    Success.
@retval #LTTNG_EVALUATION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{evaluation}
    @lt_pre_has_type{evaluation,LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED}
    @lt_pre_not_null{location}
*/
LTTNG_EXPORT extern enum lttng_evaluation_status
lttng_evaluation_session_rotation_completed_get_location(
	const struct lttng_evaluation *evaluation,
	const struct lttng_trace_archive_location **location);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_SESSION_ROTATION_H */
