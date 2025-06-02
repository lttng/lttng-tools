/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_H
#define LTTNG_CONDITION_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_cond
@{
*/

/*!
@struct lttng_condition

@brief
    Trigger condition (opaque type).
*/
struct lttng_condition;

/*!
@brief
    Trigger condition type.

Get the type of a trigger condition with lttng_condition_get_type().
*/
enum lttng_condition_type {
	/// \ref api_trigger_cond_session_consumed_size "Recording session consumed data size
	/// becomes greater than".
	LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE = 100,

	/// \ref api_trigger_cond_buffer_usage "Channel buffer usage becomes greater than".
	LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH = 101,

	/// \ref api_trigger_cond_buffer_usage "Channel buffer usage becomes less than".
	LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW = 102,

	/// \ref api_trigger_cond_rotation "Recording session rotation starts".
	LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING = 103,

	/// \ref api_trigger_cond_rotation "Recording session rotation finishes".
	LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED = 104,

	/// \ref api_trigger_cond_er_matches "Event rule matches".
	LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES = 105,

	/// Unknown (error).
	LTTNG_CONDITION_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Return type of trigger condition API functions.
*/
enum lttng_condition_status {
	/// Success.
	LTTNG_CONDITION_STATUS_OK = 0,

	/// Error.
	LTTNG_CONDITION_STATUS_ERROR = -1,

	/* Unused for the moment */
	LTTNG_CONDITION_STATUS_UNKNOWN = -2,

	/// Unsatisfied precondition.
	LTTNG_CONDITION_STATUS_INVALID = -3,

	/// Not set.
	LTTNG_CONDITION_STATUS_UNSET = -4,

	/// Unsupported feature.
	LTTNG_CONDITION_STATUS_UNSUPPORTED = -5,
};

/*!
@brief
    Returns the type of the trigger condition \lt_p{condition}.

@param[in] condition
    Trigger condition of which to get the type.

@returns
    Type of \lt_p{condition}.

@pre
    @lt_pre_not_null{condition}
*/
LTTNG_EXPORT extern enum lttng_condition_type
lttng_condition_get_type(const struct lttng_condition *condition);

/*!
@brief
    Destroys the trigger condition \lt_p{condition}.

@param[in] condition
    @parblock
    Trigger condition to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_condition_destroy(struct lttng_condition *condition);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_H */
