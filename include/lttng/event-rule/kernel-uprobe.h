/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_UPROBE_H
#define LTTNG_EVENT_RULE_KERNEL_UPROBE_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/lttng-export.h>
#include <lttng/userspace-probe.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_uprobe_er
@{
*/

/*!
@brief
    Creates a default Linux user space probe event rule for the user
    space probe location \lt_p{location}.

On success, the returned event rule has the following
condition:

<table>
  <tr>
    <th>Condition
    <th>Value
  <tr>
    <td>\ref api-er-conds-inst-pt-type "Instrumentation point type"
    <td>#LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE using \lt_p{location}
</table>

The initial event name of the returned event rule is, depending
on the type \lt_p{location}:

<dl>
  <dt>#LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION
  <dd>
    The <code>elf:</code> prefix followed with the colon-delimited
    \link lttng_userspace_probe_location_function_get_binary_path() binary path\endlink
    and
    \link lttng_userspace_probe_location_function_get_function_name() function name\endlink.

    Example: <code>elf:/usr/local/bin/my-server:acceptClient</code>.

  <dt>#LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT
  <dd>
    The <code>sdt:</code> prefix followed with the colon-delimited
    \link lttng_userspace_probe_location_tracepoint_get_binary_path() binary path\endlink,
    \link lttng_userspace_probe_location_tracepoint_get_provider_name() provider name\endlink,
    and
    \link lttng_userspace_probe_location_tracepoint_get_probe_name() probe name\endlink.

    Example: <code>sdt:/usr/local/bin/my-server:my_comp:user_cfg</code>.
</dl>

Override this initial event name with
lttng_event_rule_kernel_uprobe_set_event_name().

@param[in] location
    Location of user space probe events to match (copied).

@returns
    @parblock
    Linux user space probe event rule on success, or \c NULL on error.

    Destroy the returned event rule with
    lttng_event_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_event_rule *
lttng_event_rule_kernel_uprobe_create(const struct lttng_userspace_probe_location *location);

/*!
@brief
    Sets \lt_p{*location} to the user space probe location of the
    Linux user space probe event rule \lt_p{rule}, a copy of the
    user space probe location you passed when you called
    lttng_event_rule_kernel_uprobe_create().

See the \ref api-er-conds-inst-pt-type "instrumentation point type"
condition.

@param[in] rule
    Linux user space probe event rule of which to get the
    user space probe location.
@param[out] location
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*location}
    to the user space probe location of \lt_p{rule}.

    \lt_p{rule} owns \lt_p{*location}.

    \lt_p{*location} remains valid until the next
    function call with \lt_p{rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE}
    @lt_pre_not_null{location}
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_uprobe_get_location(const struct lttng_event_rule *rule,
					    const struct lttng_userspace_probe_location **location);

/*!
@brief
    Sets the event name of the Linux user space probe
    event rule \lt_p{rule} to \lt_p{name}.

\lt_p{name} is the name of the event which LTTng creates when
the Linux user space probe of \lt_p{rule}
(see lttng_event_rule_kernel_uprobe_get_location()) is executed.

@param[in] rule
    Linux user space probe event rule of which to set the event name.
@param[in] name
    Event name of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE}
    @lt_pre_not_null{name}
    @lt_pre_not_empty{name}

@sa lttng_event_rule_kernel_uprobe_get_event_name() --
    Get the event name of a Linux user space probe event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_uprobe_set_event_name(struct lttng_event_rule *rule, const char *name);

/*!
@brief
    Sets \lt_p{*name} to the event name of the
    Linux user space probe event rule \lt_p{rule}.

\lt_p{name} is the name of the event which LTTng creates when
the Linux user space probe of \lt_p{rule}
(see lttng_event_rule_kernel_uprobe_get_location()) is executed.

@param[in] rule
    Linux user space probe event rule of which to get the event name.
@param[out] name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*name}
    to the event name of \lt_p{rule}.

    \lt_p{rule} owns \lt_p{*name}.

    \lt_p{*name} remains valid until the next
    function call with \lt_p{rule}.
    @endparblock

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_UNSET
    \lt_p{rule} has no event name.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE}
    @lt_pre_not_null{name}

@sa lttng_event_rule_kernel_uprobe_set_event_name() --
    Set the event name of a Linux user space probe event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_uprobe_get_event_name(const struct lttng_event_rule *rule,
					      const char **name);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_KERNEL_UPROBE_H */
