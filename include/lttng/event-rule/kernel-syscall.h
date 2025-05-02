/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_SYSCALL_H
#define LTTNG_EVENT_RULE_KERNEL_SYSCALL_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_kernel_syscall_er
@{
*/

/*!
@brief
    Emission site of a Linux kernel system call.
*/
enum lttng_event_rule_kernel_syscall_emission_site {
	/// Entry and exit.
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT = 0,

	/// Entry only.
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY = 1,

	/// Exit only.
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT = 2,

	/// Unknown (error).
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_UNKNOWN = -1,
};

/*!
@brief
    Creates a default Linux kernel system call event rule for the
    emission site \lt_p{emission_site}.

On success, the returned event rule has the following
initial conditions:

<table>
  <tr>
    <th>Condition
    <th>Value
    <th>Setter
  <tr>
    <td>\ref api-er-conds-inst-pt-type "Instrumentation point type"
    <td>#LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL using \lt_p{emission_site}
    <td>Not applicable
  <tr>
    <td>\ref api-er-conds-event-name "Event name"
    <td>Any name
    <td>lttng_event_rule_kernel_syscall_set_name_pattern()
  <tr>
    <td>\ref api-er-conds-filter "Event payload and context filter"
    <td>No filter
    <td>lttng_event_rule_kernel_syscall_set_filter()
</table>

@param[in] emission_site
    Emission site of system call events to match.

@returns
    @parblock
    Linux kernel system call event rule on success, or \c NULL on error.

    Destroy the returned event rule with
    lttng_event_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_event_rule *lttng_event_rule_kernel_syscall_create(
	enum lttng_event_rule_kernel_syscall_emission_site emission_site);

/*!
@brief
    Sets the event name pattern of the Linux kernel system call
    event rule \lt_p{rule} to \lt_p{pattern}.

See the \ref api-er-conds-event-name "event name" condition.

@note
    The event name to match doesn't have any <code>sys_</code> prefix.

@param[in] rule
    Linux kernel system call event rule of which to set
    the event name pattern.
@param[in] pattern
    New event name pattern of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL}
    @lt_pre_not_null{pattern}
    @lt_pre_not_empty{pattern}

@sa lttng_event_rule_kernel_syscall_get_name_pattern() --
    Get the event name pattern of a Linux kernel system call
    event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_syscall_set_name_pattern(struct lttng_event_rule *rule,
						 const char *pattern);

/*!
@brief
    Sets \lt_p{*pattern} to the event name pattern of the
    Linux kernel system call event rule \lt_p{rule}.

See the \ref api-er-conds-event-name "event name" condition.

@param[in] rule
    Linux kernel system call event rule of which to get the
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
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL}
    @lt_pre_not_null{pattern}

@sa lttng_event_rule_kernel_syscall_set_name_pattern() --
    Set the event name pattern of a Linux kernel system call
    event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_syscall_get_name_pattern(const struct lttng_event_rule *rule,
						 const char **pattern);

/*!
@brief
    Sets the event payload and context filter of the Linux kernel
    system call event rule \lt_p{rule} to \lt_p{filter_expr}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    Linux kernel system call event rule of which to set the
    event payload and context filter.
@param[in] filter_expr
    Event payload and context filter expression of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL}
    @lt_pre_not_null{filter_expr}
    - \lt_p{filter_expr} is a valid filter expression (see
      the \ref api-er-conds-filter "event payload and context filter"
      condition).

@sa lttng_event_rule_kernel_syscall_get_filter() --
    Get the event payload and context filter of a Linux kernel
    system call event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_syscall_set_filter(struct lttng_event_rule *rule, const char *filter_expr);

/*!
@brief
    Sets \lt_p{*filter_expr} to the event payload and context filter
    expression of the Linux kernel system call event rule \lt_p{rule}.

See the \ref api-er-conds-filter "event payload and context filter"
condition.

@param[in] rule
    Linux kernel system call event rule of which to get the
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
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL}
    @lt_pre_not_null{filter_expr}

@sa lttng_event_rule_kernel_syscall_set_filter() --
    Set the event payload and context filter of a Linux kernel system
    call event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_syscall_get_filter(const struct lttng_event_rule *rule,
					   const char **filter_expr);

/*!
@brief
    Returns the emission site of system call events to match of
    the Linux kernel system call event rule \lt_p{rule}.

See the \ref api-er-conds-inst-pt-type "instrumentation point type"
condition.

@param[in] rule
    Linux kernel system call event rule of which to get the
    system call emission site.

@returns
    System call emission site of \lt_p{rule}.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL}
*/
LTTNG_EXPORT extern enum lttng_event_rule_kernel_syscall_emission_site
lttng_event_rule_kernel_syscall_get_emission_site(const struct lttng_event_rule *rule);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_KERNEL_SYSCALL_H */
