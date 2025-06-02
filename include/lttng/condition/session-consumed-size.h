/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_SESSION_CONSUMED_SIZE_H
#define LTTNG_CONDITION_SESSION_CONSUMED_SIZE_H

#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_cond_session_consumed_size
@{
*/

/*!
@brief
    Creates an initial “recording session consumed data size
    becomes greater than” trigger condition to execute
    an action when the total consumed size of the tracing
    data of all the \lt_obj_channels of a given
    \lt_obj_session becomes greater than some configured threshold.

On success, the returned trigger condition isn't valid yet; you must:

- Set a target recording session name with
  lttng_condition_session_consumed_size_set_session_name().

- Set a total consumed size threshold with
  lttng_condition_session_consumed_size_set_threshold().

@returns
    @parblock
    Trigger condition with the type
    #LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE on success,
    or \c NULL on error.

    Destroy the returned trigger condition with
    lttng_condition_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_condition *lttng_condition_session_consumed_size_create(void);

/*!
@brief
    Sets \lt_p{*threshold} to the total consumed size (bytes) threshold
    of the “recording session consumed data size becomes greater than”
    trigger condition \lt_p{condition}.

@param[in] condition
    “Recording session consumed data size becomes greater than”
    trigger condition of which to get the total consumed size threshold.
@param[out] threshold
    <strong>On success</strong>, this function sets \lt_p{*threshold}
    to the total consumed size (bytes) of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_UNSET
    \lt_p{condition} has no total consumed size threshold.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE}
    @lt_pre_not_null{threshold}

@sa lttng_condition_session_consumed_size_set_threshold() --
    Set the total consumed size threshold of a
    “recording session consumed data size becomes greater than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_session_consumed_size_get_threshold(const struct lttng_condition *condition,
						    uint64_t *threshold);

/*!
@brief
    Sets the total consumed size threshold of the
    “recording session consumed data size becomes greater than”
    trigger condition \lt_p{condition} to \lt_p{threshold} bytes.

@param[in] condition
    “Recording session consumed data size becomes greater than” trigger
    condition of which to set the total consumed size threshold.
@param[in] threshold
    Total consumed size (bytes) threshold of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE}

@sa lttng_condition_session_consumed_size_get_threshold() --
    Get the total consumed size threshold of a
    “recording session consumed data size becomes greater than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_session_consumed_size_set_threshold(struct lttng_condition *condition,
						    uint64_t threshold);

/*!
@brief
    Sets \lt_p{*session_name} to the target \lt_obj_session name of the
    “recording session consumed data size becomes greater than” trigger
    condition \lt_p{condition}.

@param[in] condition
    “Recording session consumed data size becomes greater than” trigger
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
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE}
    @lt_pre_not_null{session_name}

@sa lttng_condition_session_consumed_size_set_session_name() --
    Set the target recording session name of a
    “recording session consumed data size becomes greater than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_session_consumed_size_get_session_name(const struct lttng_condition *condition,
						       const char **session_name);

/*!
@brief
    Sets the target \lt_obj_session name of the
    “recording session consumed data size becomes greater than”
    trigger condition \lt_p{condition} to \lt_p{session_name}.

@param[in] condition
    “Recording session consumed data size becomes greater than” trigger
    condition of which to set the target recording session name.
@param[in] session_name
    Target recording session name of \lt_p{condition} (copied).

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE}
    @lt_pre_not_null{session_name}

@sa lttng_condition_session_consumed_size_get_session_name() --
    Get the target recording session name of a
    “recording session consumed data size becomes greater than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_session_consumed_size_set_session_name(struct lttng_condition *condition,
						       const char *session_name);

/*!
@brief
    Sets \lt_p{*consumed_size} to the captured total \lt_obj_session
    consumed size of the
    “recording session consumed data size becomes greater than” trigger
    condition evaluation \lt_p{evaluation}.

@param[in] evaluation
    “Recording session consumed data size becomes greater than” trigger
    condition evaluation of which to get the captured total recording
    session consumed size.
@param[out] consumed_size
    <strong>On success</strong>, this function sets
    \lt_p{*consumed_size} to the captured total recording session
    consumed size (bytes) of \lt_p{evaluation}.

@retval #LTTNG_EVALUATION_STATUS_OK
    Success.
@retval #LTTNG_EVALUATION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{evaluation}
    @lt_pre_has_type{evaluation,LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE}
    @lt_pre_not_null{consumed_size}
*/
LTTNG_EXPORT extern enum lttng_evaluation_status
lttng_evaluation_session_consumed_size_get_consumed_size(const struct lttng_evaluation *evaluation,
							 uint64_t *consumed_size);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_SESSION_CONSUMED_SIZE_H */
