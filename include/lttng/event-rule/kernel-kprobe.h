/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_KPROBE_H
#define LTTNG_EVENT_RULE_KERNEL_KPROBE_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_kprobe_er
@{
*/

struct lttng_kernel_probe_location;

/*!
@brief
    Creates a default Linux kprobe event rule for the kprobe
    location \lt_p{location}.

On success, the returned event rule has the following
condition:

<table>
  <tr>
    <th>Condition
    <th>Value
  <tr>
    <td>\ref api-er-conds-inst-pt-type "Instrumentation point type"
    <td>#LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE using \lt_p{location}
</table>

The initial event name of the returned event rule is, depending
on the type \lt_p{location}:

<dl>
  <dt>#LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET
  <dd>
    The
    \link lttng_kernel_probe_location_symbol_get_name() symbol name\endlink
    of \lt_p{location} followed with, if not zero,
    the
    \link lttng_kernel_probe_location_symbol_get_offset() offset\endlink
    from symbol of \lt_p{location} (hexadecimal with the <code>0x</code>
    prefix).

    Examples:

    - <code>copy_from_user</code>
    - <code>schedule+0x4c0</code>

  <dt>#LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS
  <dd>
    The
    \link lttng_kernel_probe_location_address_get_address() address\endlink
    within the kernel of \lt_p{location}
    (hexadecimal with the <code>0x</code> prefix).

    Example: <code>0xffffffff814abc30</code>.
</dl>

Override this initial event name with
lttng_event_rule_kernel_kprobe_set_event_name().

@param[in] location
    Location of kprobe events to match (copied).

@returns
    @parblock
    Linux kprobe event rule on success, or \c NULL on error.

    Destroy the returned event rule with
    lttng_event_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_event_rule *
lttng_event_rule_kernel_kprobe_create(const struct lttng_kernel_probe_location *location);

/*!
@brief
    Sets \lt_p{*location} to the kprobe location of the
    Linux kprobe event rule \lt_p{rule}, a copy of the
    kprobe location you passed when you called
    lttng_event_rule_kernel_kprobe_create().

See the \ref api-er-conds-inst-pt-type "instrumentation point type"
condition.

@param[in] rule
    Linux kprobe event rule of which to get the kprobe location.
@param[out] location
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*location}
    to the kprobe location of \lt_p{rule}.

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
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE}
    @lt_pre_not_null{location}
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_kprobe_get_location(const struct lttng_event_rule *rule,
					    const struct lttng_kernel_probe_location **location);

/*!
@brief
    Sets the event name of the Linux kprobe
    event rule \lt_p{rule} to \lt_p{name}.

\lt_p{name} is the name of the event which LTTng creates when
the Linux kprobe of \lt_p{rule}
(see lttng_event_rule_kernel_kprobe_get_location()) is executed.

@param[in] rule
    Linux kprobe event rule of which to set the event name.
@param[in] name
    Event name of \lt_p{rule} (copied).

@retval #LTTNG_EVENT_RULE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE}
    @lt_pre_not_null{name}
    @lt_pre_not_empty{name}

@sa lttng_event_rule_kernel_kprobe_get_event_name() --
    Get the event name of a Linux kprobe event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_kprobe_set_event_name(struct lttng_event_rule *rule, const char *name);

/*!
@brief
    Sets \lt_p{*name} to the event name of the
    Linux kprobe event rule \lt_p{rule}.

\lt_p{name} is the name of the event which LTTng creates when
the Linux kprobe of \lt_p{rule}
(see lttng_event_rule_kernel_kprobe_get_location()) is executed.

@param[in] rule
    Linux kprobe event rule of which to get the event name.
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
    @lt_pre_has_type{rule,LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE}
    @lt_pre_not_null{name}

@sa lttng_event_rule_kernel_kprobe_set_event_name() --
    Set the event name of a Linux kprobe event rule.
*/
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_kprobe_get_event_name(const struct lttng_event_rule *rule,
					      const char **name);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_KERNEL_KPROBE_H */
