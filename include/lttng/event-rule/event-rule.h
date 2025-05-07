/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_H
#define LTTNG_EVENT_RULE_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_er
@{
*/

/*!
@struct lttng_event_rule

@brief
    Event rule (opaque type).
*/
struct lttng_event_rule;

/*!
@brief
    Event rule type.

See the
\ref api-er-conds-inst-pt-type "instrumentation point type" condition.

Get the type of an event rule with lttng_event_rule_get_type().
*/
enum lttng_event_rule_type {
	/// Match \ref api_kernel_tp_er "LTTng kernel tracepoints".
	LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT = 2,

	/// Match \ref api_kernel_syscall_er "Linux kernel system calls".
	LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL = 0,

	/// Match \ref api_kprobe_er "Linux kprobes".
	LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE = 1,

	/// Match \ref api_uprobe_er "Linux user space probes".
	LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE = 3,

	/// Match \ref api_user_tp_er "LTTng user space tracepoints".
	LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT = 4,

	/// Match \link api_jul_er \lt_jul (JUL) logging statements\endlink.
	LTTNG_EVENT_RULE_TYPE_JUL_LOGGING = 5,

	/// Match \link api_log4j1_er \lt_log4j1 logging statements\endlink.
	LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING = 6,

	/// Match \link api_log4j2_er \lt_log4j2 logging statements\endlink.
	LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING = 8,

	/// Match \ref api_py_er "Python logging statements".
	LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING = 7,

	/// Unknown (error).
	LTTNG_EVENT_RULE_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Return type of event rule API functions.
*/
enum lttng_event_rule_status {
	/// Success.
	LTTNG_EVENT_RULE_STATUS_OK = 0,

	/// Error.
	LTTNG_EVENT_RULE_STATUS_ERROR = -1,

	/* Unused for the moment */
	LTTNG_EVENT_RULE_STATUS_UNKNOWN = -2,

	/// Unsatisfied precondition.
	LTTNG_EVENT_RULE_STATUS_INVALID = -3,

	/// Not set.
	LTTNG_EVENT_RULE_STATUS_UNSET = -4,

	/// Unsupported.
	LTTNG_EVENT_RULE_STATUS_UNSUPPORTED = -5,
};

/*!
@brief
    Returns the type of the event rule \lt_p{rule}.

@param[in] rule
    Event rule of which to get the type.

@returns
    Type of \lt_p{rule}.

@pre
    @lt_pre_not_null{rule}
*/
LTTNG_EXPORT extern enum lttng_event_rule_type
lttng_event_rule_get_type(const struct lttng_event_rule *rule);

/*!
@brief
    Destroys the event rule \lt_p{rule}.

@param[in] rule
    @parblock
    Event rule to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_event_rule_destroy(struct lttng_event_rule *rule);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_H */
