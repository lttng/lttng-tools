/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_TRACEPOINT_H
#define LTTNG_EVENT_RULE_KERNEL_TRACEPOINT_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/event.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_kernel_tp_er
@{
*/

/*!
@brief
    Creates a default LTTng kernel tracepoint event rule.

On success, the returned event rule has the following
initial conditions:

<table>
  <tr>
    <th>Condition
    <th>Value
    <th>Setter
  <tr>
    <td>\ref api-er-conds-inst-pt-type "Instrumentation point type"
    <td>#LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT
    <td>Not applicable
  <tr>
    <td>\ref api-er-conds-event-name "Event name"
    <td>Any name
    <td>lttng_event_rule_kernel_tracepoint_set_name_pattern()
  <tr>
    <td>\ref api-er-conds-filter "Event payload and context filter"
    <td>No filter
    <td>lttng_event_rule_kernel_tracepoint_set_filter()
</table>

@returns
    @parblock
    LTTng kernel tracepoint event rule on success, or \c NULL on error.

    Destroy the returned event rule with
    lttng_event_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_event_rule *lttng_event_rule_kernel_tracepoint_create(void);

/*!
@brief
    Sets the event name pattern of the LTTng kernel tracepoint
    event rule \lt_p{rule} to \lt_p{pattern}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    LTTng kernel tracepoint event rule of which to set
    the event name pattern.
@param[in] pattern
    New event name pattern of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT}
    @lt_pre_not_null{pattern}
    @lt_pre_not_empty{pattern}

@sa lttng_event_rule_kernel_tracepoint_get_name_pattern() --
    Get the event name pattern of an LTTng kernel tracepoint
    event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_tracepoint_set_name_pattern(struct lttng_event_rule *rule,
						    const char *pattern);

/*!
@brief
    Sets \lt_p{*pattern} to the event name pattern of the
    LTTng kernel tracepoint event rule \lt_p{rule}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    LTTng kernel tracepoint event rule of which to get the
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
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT}
    @lt_pre_not_null{pattern}

@sa lttng_event_rule_kernel_tracepoint_set_name_pattern() --
    Set the event name pattern of an LTTng kernel tracepoint
    event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_tracepoint_get_name_pattern(const struct lttng_event_rule *rule,
						    const char **pattern);

/*!
@brief
    Sets the event payload and context filter of the LTTng kernel
    tracepoint event rule \lt_p{rule} to \lt_p{filter_expr}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    LTTng kernel tracepoint event rule of which to set the
    event payload and context filter.
@param[in] filter_expr
    Event payload and context filter expression of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT}
    @lt_pre_not_null{filter_expr}
    - \lt_p{filter_expr} is a valid filter expression (see
      the \ref api-er-conds-filter "event payload and context filter"
      condition).

@sa lttng_event_rule_kernel_tracepoint_get_filter() --
    Get the event payload and context filter of an LTTng kernel
    tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_tracepoint_set_filter(struct lttng_event_rule *rule,
					      const char *filter_expr);

/*!
@brief
    Sets \lt_p{*filter_expr} to the event payload and context filter
    expression of the LTTng kernel tracepoint event rule \lt_p{rule}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    LTTng kernel tracepoint event rule of which to get the
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
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT}
    @lt_pre_not_null{filter_expr}

@sa lttng_event_rule_kernel_tracepoint_set_filter() --
    Set the event payload and context filter of an LTTng
    kernel tracepoint event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_tracepoint_get_filter(const struct lttng_event_rule *rule,
					      const char **filter_expr);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_KERNEL_TRACEPOINT_H */
