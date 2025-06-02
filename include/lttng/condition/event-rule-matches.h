/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_EVENT_RULE_MATCHES_H
#define LTTNG_CONDITION_EVENT_RULE_MATCHES_H

#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_cond_er_matches
@{
*/

struct lttng_event_expr;
struct lttng_event_field_value;

/*!
@brief
    Return type of
    lttng_evaluation_event_rule_matches_get_captured_values().
*/
enum lttng_evaluation_event_rule_matches_status {
	/// Success.
	LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_OK = 0,

	/// The condition of the evaluation has no capture descriptors.
	LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_NONE = 1,

	/// Unsatisfied precondition.
	LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_INVALID = -1,
};

/*!
@brief
    Creates an “event rule matches” trigger condition to execute
    an action when the event rule \lt_p{rule} matches
    an LTTng event.

On success, the returned trigger condition has no
capture descriptors: append capture descriptors with
lttng_condition_event_rule_matches_append_capture_descriptor().

@param[in] rule
    Event rule of the “event rule matches” trigger condition
    to create (not moved).

@returns
    @parblock
    Trigger condition with the type
    #LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES on success,
    or \c NULL on error.

    Destroy the returned trigger condition with
    lttng_condition_destroy().
    @endparblock

@pre
    @lt_pre_not_null{rule}
*/
LTTNG_EXPORT extern struct lttng_condition *
lttng_condition_event_rule_matches_create(struct lttng_event_rule *rule);

/*!
@brief
    Sets \lt_p{*rule} to the event rule of the
    “event rule matches” trigger condition \lt_p{condition}.

@param[in] condition
    “Event rule matches” trigger condition of which to get the
    event rule.
@param[out] rule
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*rule}
    to the event rule of \lt_p{condition}.

    \lt_p{condition} owns \lt_p{*rule}.

    \lt_p{*rule} remains valid until the next
    function call with \lt_p{condition}.
    @endparblock

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES}
    @lt_pre_not_null{rule}
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_event_rule_matches_get_rule(const struct lttng_condition *condition,
					    const struct lttng_event_rule **rule);

/*!
@brief
    Sets \lt_p{*field_val} to the array event field value of
    the “event rule matches” trigger condition evaluation
    \lt_p{evaluation} containing its captured field values.

Each element of the returned array event field value is described
by the capture descriptor at the same index in the condition
of \lt_p{evaluation}
(see
lttng_condition_event_rule_matches_get_capture_descriptor_count()
and
lttng_condition_event_rule_matches_get_capture_descriptor_at_index()).

@param[in] evaluation
    “Event rule matches” trigger condition evaluation of which to get
    the captured event field values.
@param[out] field_val
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*field_val}
    to the captured event field values of \lt_p{evaluation}.

    \lt_p{*field_val} has the type #LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY.

    \lt_p{evaluation} owns \lt_p{*field_val}.

    \lt_p{*field_val} remains valid until the next
    function call with \lt_p{evaluation}.
    @endparblock

@retval #LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_OK
    Success.
@retval #LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_NONE
    The condition of \lt_p{evaluation} has no capture descriptors.
@retval #LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{evaluation}
    @lt_pre_has_type{evaluation,LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES}
    @lt_pre_not_null{field_val}
*/
LTTNG_EXPORT extern enum lttng_evaluation_event_rule_matches_status
lttng_evaluation_event_rule_matches_get_captured_values(
	const struct lttng_evaluation *evaluation,
	const struct lttng_event_field_value **field_val);

/*!
@brief
    Appends a capture descriptor with the event expression \lt_p{expr}
    to the “event rule matches” trigger condition \lt_p{condition}.

When a trigger with \lt_p{condition} fires, LTTng evaluates \lt_p{expr}
and captures the result. With the
\link api_trigger_action_notify “notify”\endlink action, a user may read
the captured values from the condition evaluation with
lttng_evaluation_event_rule_matches_get_captured_values().

@param[in] condition
    “Event rule matches” trigger condition to which to append
    a capture descriptor.
@param[in] expr
    @parblock
    Event expression of the capture descriptor to append to
    \lt_p{condition}.

    <strong>On success</strong>, the ownership of this expression is
    moved to \lt_p{condition}.
    @endparblock

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_CONDITION_STATUS_UNSUPPORTED
    \lt_p{condition} doesn't support event field value capturing
    considering its event rule.
@retval #LTTNG_CONDITION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{condition}
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES}
    @lt_pre_not_null{expr}
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_event_rule_matches_append_capture_descriptor(struct lttng_condition *condition,
							     struct lttng_event_expr *expr);

/*!
@brief
    Sets \lt_p{*count} to the number of capture descriptors
    of the “event rule matches” trigger condition \lt_p{condition}.

@param[in] condition
    “Event rule matches” trigger condition of which to get
    the number of capture descriptors.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count}
    to the number of capture descriptors of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES}
    @lt_pre_not_null{count}

@sa lttng_condition_event_rule_matches_get_capture_descriptor_at_index() --
    Get the capture descriptor of an “event rule matches”
    trigger condition by index.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_event_rule_matches_get_capture_descriptor_count(
	const struct lttng_condition *condition, unsigned int *count);

/*!
@brief
    Returns the capture descriptor of the “event rule matches” trigger
    condition \lt_p{condition} at the index \lt_p{index}.

@param[in] condition
    “Event rule matches” trigger condition of which to get
    the capture descriptor at the index \lt_p{index}.
@param[in] index
    Index of the capture descriptor to get from \lt_p{condition}.

@returns
    @parblock
    Capture descriptor of the “event rule matches” trigger condition
    \lt_p{condition} at the index \lt_p{index}, or \c NULL on error.

    \lt_p{condition} owns the returned capture descriptor.

    The returned capture descriptor remains valid as long
    as \lt_p{condition} exists.
    @endparblock

@pre
    @lt_pre_not_null{condition}
    @lt_pre_has_type{condition,LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES}
    - \lt_p{index} is less than the number of capture descriptors
      (as returned by
      lttng_condition_event_rule_matches_get_capture_descriptor_count())
      of \lt_p{condition}.

@sa lttng_condition_event_rule_matches_get_capture_descriptor_count() --
    Get the number of capture descriptors of an “event rule matches”
    trigger condition.
*/
LTTNG_EXPORT extern const struct lttng_event_expr *
lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
	const struct lttng_condition *condition, unsigned int index);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_EVENT_RULE_MATCHES_H */
