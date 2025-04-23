/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * SPDX-FileCopyrightText: 2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CLEAR_HANDLE_H
#define LTTNG_CLEAR_HANDLE_H

#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_session_clear
@{
*/

/*!
@struct lttng_clear_handle

@brief
    \lt_obj_c_session clearing handle (opaque type).
*/
struct lttng_clear_handle;

/*!
@brief
    Return type of \lt_obj_session clearing handle functions.

Error status enumerators have a negative value.
*/
enum lttng_clear_handle_status {
	/// Success.
	LTTNG_CLEAR_HANDLE_STATUS_OK = 0,

	/// Recording session clearing operation completed.
	LTTNG_CLEAR_HANDLE_STATUS_COMPLETED = 1,

	/// Timeout reached.
	LTTNG_CLEAR_HANDLE_STATUS_TIMEOUT = 2,

	/// Unsatisfied precondition.
	LTTNG_CLEAR_HANDLE_STATUS_INVALID = -1,

	/// Other error.
	LTTNG_CLEAR_HANDLE_STATUS_ERROR = -2,
};

/*!
@brief
    Destroys the \lt_obj_session clearing handle \lt_p{handle}.

@param[in] handle
    @parblock
    Recording session clearing handle to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_clear_handle_destroy(struct lttng_clear_handle *handle);

/*!
@brief
    Waits for the \lt_obj_session clearing operation identified by
    \lt_p{handle} to complete.

If this function returns #LTTNG_CLEAR_HANDLE_STATUS_COMPLETED, then the
recording session clearing operation identified by \lt_p{handle}
completed. This doesn't mean, however, that the clearing operation
itself succeeded; use lttng_clear_handle_get_result() to know this.

@param[in] handle
    Recording session clearing handle which identifies the clearing
    operation of which to wait for completion.
@param[in] timeout_ms
    Maximum time (milliseconds) to wait for the completion of the
    recording session clearing operation identified by \lt_p{handle}
    before returning #LTTNG_CLEAR_HANDLE_STATUS_TIMEOUT, or
    <code>-1</code> to wait indefinitely.

@retval #LTTNG_CLEAR_HANDLE_STATUS_COMPLETED
    The recording session clearing operation identified by \lt_p{handle}
    completed (with or without success).
@retval #LTTNG_CLEAR_HANDLE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_CLEAR_HANDLE_STATUS_TIMEOUT
    The function waited for the completion of the recording session
    clearing operation for more than \lt_p{timeout_ms}&nbsp;ms.
@retval #LTTNG_CLEAR_HANDLE_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{handle}

@sa lttng_clear_handle_get_result() --
    Returns whether or not a recording session clearing operation
    succeeded.
*/
LTTNG_EXPORT extern enum lttng_clear_handle_status
lttng_clear_handle_wait_for_completion(struct lttng_clear_handle *handle, int timeout_ms);

/*!
@brief
    Sets \lt_p{*result} to the result of the \lt_obj_session clearing
    operation identified by \lt_p{handle}.

You must successfully wait for the completion of the recording session
clearing operation identified by \lt_p{handle} with
lttng_clear_handle_wait_for_completion() before you call this function.

On success, \lt_p{*result} is #LTTNG_OK if the clearing operation was
successful.

@param[in] handle
    Handle of the recording session clearing operation of which to get
    the result.
@param[out] result
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*result} to
    the result of the recording session clearing operation identified by
    \lt_p{handle}.

    \lt_p{*result} is #LTTNG_OK if the clearing operation was
    successful.
    @endparblock

@retval #LTTNG_CLEAR_HANDLE_STATUS_OK
    Success: \lt_p{*result} is the result of the recording session
    clearing operation identified by \lt_p{handle}.
@retval #LTTNG_CLEAR_HANDLE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_CLEAR_HANDLE_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{handle}
    - You successfully waited for the completion of the recording session
      clearing operation identified by \lt_p{handle} with
      lttng_clear_handle_wait_for_completion().
    @lt_pre_not_null{result}

@sa lttng_clear_handle_wait_for_completion() --
    Waits for a recording session clearing operation to complete.
*/
LTTNG_EXPORT extern enum lttng_clear_handle_status
lttng_clear_handle_get_result(const struct lttng_clear_handle *handle,
			      enum lttng_error_code *result);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CLEAR_HANDLE_H */
