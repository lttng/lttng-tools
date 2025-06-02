/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_H
#define LTTNG_ACTION_H

#include <lttng/lttng-export.h>

struct lttng_action;

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_action
@{
*/

/*!
@brief
    Trigger action type.

Get the type of a trigger action with
lttng_action_get_type().
*/
enum lttng_action_type {
	/// \ref api_trigger_action_notify "Notify".
	LTTNG_ACTION_TYPE_NOTIFY = 0,

	/// \ref api_trigger_action_start_session "Start recording session".
	LTTNG_ACTION_TYPE_START_SESSION = 1,

	/// \ref api_trigger_action_stop_session "Stop recording session".
	LTTNG_ACTION_TYPE_STOP_SESSION = 2,

	/// \ref api_trigger_action_rotate "Rotate recording session snapshot".
	LTTNG_ACTION_TYPE_ROTATE_SESSION = 3,

	/// \ref api_trigger_action_snapshot "Take recording session snapshot".
	LTTNG_ACTION_TYPE_SNAPSHOT_SESSION = 4,

	/// \ref api_trigger_action_list "Trigger action list".
	LTTNG_ACTION_TYPE_LIST = 5,

	/// Unknown (error).
	LTTNG_ACTION_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Return type of trigger action API functions.
*/
enum lttng_action_status {
	/// Success.
	LTTNG_ACTION_STATUS_OK = 0,

	/// Error.
	LTTNG_ACTION_STATUS_ERROR = -1,

	/* Unused for the moment */
	LTTNG_ACTION_STATUS_UNKNOWN = -2,

	/// Unsatisfied precondition.
	LTTNG_ACTION_STATUS_INVALID = -3,

	/// Not set.
	LTTNG_ACTION_STATUS_UNSET = -4,
};

/*!
@brief
    Returns the type of the trigger action \lt_p{action}.

@param[in] action
    Trigger action of which to get the type.

@returns
    Type of \lt_p{action}.

@pre
    @lt_pre_not_null{action}
*/
LTTNG_EXPORT extern enum lttng_action_type lttng_action_get_type(const struct lttng_action *action);

/*!
@brief
    Destroys the trigger action \lt_p{action}.

@param[in] action
    @parblock
    Trigger action to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_action_destroy(struct lttng_action *action);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_H */
