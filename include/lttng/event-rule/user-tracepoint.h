/*
 * SPDX-FileCopyrightText: 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_USER_TRACEPOINT_H
#define LTTNG_EVENT_RULE_USER_TRACEPOINT_H

#include <lttng/domain.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event.h>
#include <lttng/log-level-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_user_tp_er
@{
*/

/*!
@brief
    Creates a default LTTng user space tracepoint event rule.

On success, the returned event rule has the following
initial conditions:

<table>
  <tr>
    <th>Condition
    <th>Value
    <th>Setter(s)
  <tr>
    <td>\ref api-er-conds-inst-pt-type "Instrumentation point type"
    <td>#LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT
    <td>Not applicable
  <tr>
    <td>\ref api-er-conds-event-name "Event name"
    <td>Any name
    <td>
      - lttng_event_rule_user_tracepoint_set_name_pattern()
      - lttng_event_rule_user_tracepoint_add_name_pattern_exclusion()
  <tr>
    <td>\ref api-er-conds-ll "Instrumentation point log level"
    <td>Any log level
    <td>lttng_event_rule_user_tracepoint_set_log_level_rule()
  <tr>
    <td>\ref api-er-conds-filter "Event payload and context filter"
    <td>No filter
    <td>lttng_event_rule_user_tracepoint_set_filter()
</table>

@returns
    @parblock
    LTTng user space tracepoint event rule on success,
    or \c NULL on error.

    Destroy the returned event rule with lttng_event_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_event_rule *lttng_event_rule_user_tracepoint_create(void);

/*!
@brief
    Sets the event name pattern of the LTTng user space tracepoint
    event rule \lt_p{rule} to \lt_p{pattern}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    LTTng user space tracepoint event rule of which to set the
    event name pattern.
@param[in] pattern
    New event name pattern of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{pattern}
    @lt_pre_not_empty{pattern}

@sa lttng_event_rule_user_tracepoint_get_name_pattern() --
    Get the event name pattern of an LTTng user space tracepoint
    event rule.
@sa lttng_event_rule_user_tracepoint_add_name_pattern_exclusion() --
    Add an event name exclusion pattern to an LTTng user space
    tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_set_name_pattern(struct lttng_event_rule *rule,
						  const char *pattern);

/*!
@brief
    Sets \lt_p{*pattern} to the event name pattern of the
    LTTng user space tracepoint event rule \lt_p{rule}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    LTTng user space tracepoint event rule of which to get the
    event name pattern.
@param[out] pattern
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*pattern}
    to the event name pattern of \lt_p{rule}.

    \lt_p{rule} owns \lt_p{*pattern}.

    \lt_p{*pattern} remains valid until the next
    function call with \lt_p{rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_UNSET
    \lt_p{rule} has no event name pattern, which corresponds to
    the pattern <code>*</code> (any event name).
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{pattern}

@sa lttng_event_rule_user_tracepoint_set_name_pattern() --
    Set the event name pattern of an LTTng user space tracepoint
    event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_get_name_pattern(const struct lttng_event_rule *rule,
						  const char **pattern);

/*!
@brief
    Sets the event payload and context filter of the LTTng user space
    tracepoint event rule \lt_p{rule} to \lt_p{filter_expr}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    LTTng user space tracepoint event rule of which to set the
    event payload and context filter.
@param[in] filter_expr
    Event payload and context filter expression of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{filter_expr}
    - \lt_p{filter_expr} is a valid filter expression (see
      the \ref api-er-conds-filter "event payload and context filter"
      condition).

@sa lttng_event_rule_user_tracepoint_get_filter() --
    Get the event payload and context filter of an LTTng
    user space tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_set_filter(struct lttng_event_rule *rule, const char *filter_expr);

/*!
@brief
    Sets \lt_p{*filter_expr} to the event payload and context filter
    expression of the LTTng user space tracepoint
    event rule \lt_p{rule}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    LTTng user space tracepoint event rule of which to get the
    event payload and context filter.
@param[out] filter_expr
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*filter_expr}
    to the event payload and context filter expression of \lt_p{rule}.

    \lt_p{rule} owns \lt_p{*filter_expr}.

    \lt_p{*filter_expr} remains valid until the next
    function call with \lt_p{rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_UNSET
    \lt_p{rule} has no event payload and context filter, which
    corresponds to the filter expression <code>1</code>.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{filter_expr}

@sa lttng_event_rule_user_tracepoint_set_filter() --
    Set the event payload and context filter of an LTTng
    user space tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_get_filter(const struct lttng_event_rule *rule,
					    const char **filter_expr);

/*!
@brief
    Sets the instrumentation point log level rule of the LTTng user
    space tracepoint event rule
    \lt_p{event_rule} to \lt_p{log_level_rule}.

See the \ref api-er-conds-ll "instrumentation point log level"
condition.

@param[in] event_rule
    LTTng user space tracepoint event rule of which to set the
    instrumentation point log level rule.
@param[in] log_level_rule
    Instrumentation point log level rule of \lt_p{event_rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{event_rule}
    @lt_pre_has_type{event_rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{log_level_rule}

@sa lttng_event_rule_user_tracepoint_get_log_level_rule() --
    Get the instrumentation point log level rule of an LTTng user space
    tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_set_log_level_rule(
	struct lttng_event_rule *event_rule, const struct lttng_log_level_rule *log_level_rule);

/*!
@brief
    Sets \lt_p{*log_level_rule} to the instrumentation point log level
    rule of the LTTng user space tracepoint event rule
    \lt_p{event_rule}.

See the \ref api-er-conds-ll "instrumentation point log level"
condition.

@param[in] event_rule
    LTTng user space tracepoint event rule of which to get the
    instrumentation point log level rule.
@param[out] log_level_rule
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*log_level_rule} to the instrumentation point log level
    rule of \lt_p{event_rule}.

    \lt_p{event_rule} owns \lt_p{*log_level_rule}.

    \lt_p{*log_level_rule} remains valid until the next
    function call with \lt_p{event_rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_UNSET
    \lt_p{event_rule} has no instrumentation point log level rule.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{log_level_rule}

@sa lttng_event_rule_user_tracepoint_set_log_level_rule() --
    Set the instrumentation point log level rule of an LTTng user space
    tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_get_log_level_rule(
	const struct lttng_event_rule *event_rule,
	const struct lttng_log_level_rule **log_level_rule);

/*!
@brief
    Adds the event name exclusion pattern \lt_p{exclusion_pattern} to
    the LTTng user space tracepoint event rule \lt_p{rule}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    LTTng user space tracepoint event rule to which to add the
    event name exclusion pattern
    \lt_p{exclusion_pattern}.
@param[in] exclusion_pattern
    Event name exclusion pattern to add to \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{exclusion_pattern}

@sa lttng_event_rule_user_tracepoint_set_name_pattern() --
    Set the event name pattern of an LTTng user space tracepoint
    event rule.
@sa lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index() --
    Get an event name exclusion pattern of an LTTng
    user space tracepoint event rule by index.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_add_name_pattern_exclusion(struct lttng_event_rule *rule,
							    const char *exclusion_pattern);

/*!
@brief
    Sets \lt_p{*count} to the number of event name exclusion patterns
    of the LTTng user space tracepoint event rule \lt_p{rule}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    LTTng user space tracepoint event rule of which to get
    the number of event name exclusion patterns.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count}
    to the number of event name exclusion patterns of \lt_p{rule}.

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    @lt_pre_not_null{count}

@sa lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index() --
    Get an event name exclusion pattern of an LTTng
    user space tracepoint event rule by index.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
	const struct lttng_event_rule *rule, unsigned int *count);

/*!
@brief
    Sets \lt_p{*exclusion_pattern} to the event name exclusion pattern
    of the LTTng user space tracepoint event rule \lt_p{rule}
    at the index \lt_p{index}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    LTTng user space tracepoint event rule of which to get the
    event name exclusion pattern at the index \lt_p{index}.
@param[in] index
    Index of the event name exclusion pattern to get from \lt_p{rule}.
@param[in] exclusion_pattern
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*exclusion_pattern} to the event name exclusion pattern
    of \lt_p{rule} at the index \lt_p{index}.

    \lt_p{event_rule} owns \lt_p{*exclusion_pattern}.

    \lt_p{*exclusion_pattern} remains valid until the next
    function call with \lt_p{event_rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT}
    - \lt_p{index} is less than the number of event name exclusion
      patterns of \lt_p{rule} (as given by
      lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count()).
    @lt_pre_not_null{exclusion_pattern}

@sa lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count() --
    Get the number of event name exclusion patterns of an LTTng
    user space tracepoint event rule.
@sa lttng_event_rule_user_tracepoint_add_name_pattern_exclusion() --
    Adds an event name exclusion pattern to an LTTng
    user space tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
	const struct lttng_event_rule *rule, unsigned int index, const char **exclusion_pattern);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_USER_TRACEPOINT_H */
