/*
 * SPDX-FileCopyrightText: 2024 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_LOG4J2_LOGGING_H
#define LTTNG_EVENT_RULE_LOG4J2_LOGGING_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/event.h>
#include <lttng/log-level-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_log4j2_er
@{
*/

/*!
@brief
    Creates a default \lt_log4j2 event rule.

On success, the returned event rule has the following
initial conditions:

<table>
  <tr>
    <th>Condition
    <th>Value
    <th>Setter
  <tr>
    <td>\ref api-er-conds-inst-pt-type "Instrumentation point type"
    <td>#LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING
    <td>Not applicable
  <tr>
    <td>\ref api-er-conds-event-name "Event name"
    <td>Any name
    <td>lttng_event_rule_log4j2_logging_set_name_pattern()
  <tr>
    <td>\ref api-er-conds-ll "Instrumentation point log level"
    <td>Any log level
    <td>lttng_event_rule_log4j2_logging_set_log_level_rule()
  <tr>
    <td>\ref api-er-conds-filter "Event payload and context filter"
    <td>No filter
    <td>lttng_event_rule_log4j2_logging_set_filter()
</table>

@returns
    @parblock
    \lt_log4j2 event rule on success, or \c NULL on error.

    Destroy the returned event rule with lttng_event_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_event_rule *lttng_event_rule_log4j2_logging_create(void);

/*!
@brief
    Sets the event name pattern of the \lt_log4j2 event rule \lt_p{rule}
    to \lt_p{pattern}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    \lt_log4j2 event rule of which to set the event name pattern.
@param[in] pattern
    New event name pattern of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING}
    @lt_pre_not_null{pattern}
    @lt_pre_not_empty{pattern}

@sa lttng_event_rule_log4j2_logging_get_name_pattern() --
    Get the event name pattern of an \lt_log4j2 event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j2_logging_set_name_pattern(struct lttng_event_rule *rule,
						 const char *pattern);

/*!
@brief
    Sets \lt_p{*pattern} to the event name pattern of the \lt_log4j2
    event rule \lt_p{rule}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    \lt_log4j2 event rule of which to get the event name pattern.
@param[out] pattern
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*pattern} to
    the event name pattern of \lt_p{rule}.

    \lt_p{rule} owns \lt_p{*pattern}.

    \lt_p{*pattern} remains valid until the next function call
    with \lt_p{rule}.
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
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING}
    @lt_pre_not_null{pattern}

@sa lttng_event_rule_log4j2_logging_set_name_pattern() --
    Set the event name pattern of an \lt_log4j2 event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j2_logging_get_name_pattern(const struct lttng_event_rule *rule,
						 const char **pattern);

/*!
@brief
    Sets the event payload and context filter of the \lt_log4j2
    event rule \lt_p{rule} to \lt_p{filter_expr}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    \lt_log4j2 event rule of which to set the filter.
@param[in] filter_expr
    Event payload and context filter expression of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING}
    @lt_pre_not_null{filter_expr}
    - \lt_p{filter_expr} is a valid filter expression (see
      the \ref api-er-conds-filter "event payload and context filter"
      condition).

@sa lttng_event_rule_log4j2_logging_get_filter() --
    Get the event payload and context filter of an \lt_log4j2 event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j2_logging_set_filter(struct lttng_event_rule *rule, const char *filter_expr);

/*!
@brief
    Sets \lt_p{*filter_expr} to the event payload and context filter
    expression of the \lt_log4j2 event rule \lt_p{rule}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    \lt_log4j2 event rule of which to get the
    event payload and context filter.
@param[out] filter_expr
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*filter_expr}
    to the filter expression of \lt_p{rule}.

    \lt_p{rule} owns \lt_p{*filter_expr}.

    \lt_p{*filter_expr} remains valid until the next function call
    with \lt_p{rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_UNSET
    \lt_p{rule} has no event payload and context filter,
    which corresponds to the filter expression <code>1</code>.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING}
    @lt_pre_not_null{expression}

@sa lttng_event_rule_log4j2_logging_set_filter() --
    Set the event payload and context filter of an \lt_log4j2
    event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j2_logging_get_filter(const struct lttng_event_rule *rule,
					   const char **filter_expr);

/*!
@brief
    Sets the instrumentation point log level rule of the \lt_log4j2
    event rule \lt_p{event_rule} to \lt_p{log_level_rule}.

See the \ref api-er-conds-ll "instrumentation point log level"
condition.

@param[in] event_rule
    \lt_log4j2 event rule of which to set the log level rule.
@param[in] log_level_rule
    Log level rule of \lt_p{event_rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{event_rule}
    @lt_pre_has_type{event_rule,LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING}
    @lt_pre_not_null{log_level_rule}

@sa lttng_event_rule_log4j2_logging_get_log_level_rule() --
    Get the log level rule of an \lt_log4j2 event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status lttng_event_rule_log4j2_logging_set_log_level_rule(
	struct lttng_event_rule *event_rule, const struct lttng_log_level_rule *log_level_rule);

/*!
@brief
    Sets \lt_p{*log_level_rule} to the instrumentation point
    log level rule of the \lt_log4j2 event rule \lt_p{event_rule}.

See the \ref api-er-conds-ll "instrumentation point log level"
condition.

@param[in] event_rule
    \lt_log4j2 event rule of which to get the log level rule.
@param[out] log_level_rule
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*log_level_rule} to the log level rule of \lt_p{event_rule}.

    \lt_p{event_rule} owns \lt_p{*log_level_rule}.

    \lt_p{*log_level_rule} remains valid until the next function call
    with \lt_p{event_rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_UNSET
    \lt_p{event_rule} has no log level rule.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{event_rule}
    @lt_pre_has_type{event_rule,LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING}
    @lt_pre_not_null{log_level_rule}

@sa lttng_event_rule_log4j2_logging_set_log_level_rule() --
    Set the log level rule of an \lt_log4j2 event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status lttng_event_rule_log4j2_logging_get_log_level_rule(
	const struct lttng_event_rule *event_rule,
	const struct lttng_log_level_rule **log_level_rule);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_LOG4J2_LOGGING_H */
