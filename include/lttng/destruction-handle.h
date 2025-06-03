/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_DESTRUCTION_HANDLE_H
#define LTTNG_DESTRUCTION_HANDLE_H

#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>
#include <lttng/rotation.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_session_destr_handle
@{
*/

/*!
@struct lttng_destruction_handle

@brief
    Recording session destruction handle (opaque type).
*/
struct lttng_destruction_handle;

/*!
@brief
    Return type of recording session destruction handle fuctions.

Error status enumerators have a negative value.
*/
enum lttng_destruction_handle_status {
	/// Success.
	LTTNG_DESTRUCTION_HANDLE_STATUS_OK = 0,

	/// Recording session destruction operation completed.
	LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED = 1,

	/// Timeout reached.
	LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT = 2,

	/// Unsatisfied precondition.
	LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID = -1,

	/// Other error.
	LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR = -2,
};

/*!
@brief
    Destroys the recording session destruction handle \lt_p{handle}.

@param[in] handle
    @parblock
    Recording session destruction handle to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_destruction_handle_destroy(struct lttng_destruction_handle *handle);

/*!
@brief
    Waits for the recording session destruction operation identified by
    \lt_p{handle} to complete.

If this function returns #LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED,
then the recording session destruction operation identified by
\lt_p{handle} completed. This doesn't mean, however, that the
destruction operation itself succeeded; use
lttng_destruction_handle_get_result() to know this.

@param[in] handle
    Recording session destruction handle which identifies the
    destruction operation of which to wait for completion.
@param[in] timeout_ms
    Maximum time (milliseconds) to wait for the completion of the
    recording session destruction operation identified by \lt_p{handle}
    before returning #LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT, or
    <code>-1</code> to wait indefinitely.

@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED
    The recording session destruction operation identified by
    \lt_p{handle} completed (with or without success).
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT
    The function waited for the completion of the recording session
    destruction operation for more than \lt_p{timeout_ms}&nbsp;ms.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{handle}

@sa lttng_destruction_handle_get_result() --
    Returns whether or not a recording session destruction operation
    succeeded.
*/
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_wait_for_completion(struct lttng_destruction_handle *handle,
					     int timeout_ms);

/*!
@brief
    Sets \lt_p{*result} to the result of the recording session
    destruction operation identified by \lt_p{handle}.

You must successfully wait for the completion of the recording session
destruction operation identified by \lt_p{handle} with
lttng_destruction_handle_wait_for_completion() before you call this function.

On success, \lt_p{*result} is #LTTNG_OK if the destruction operation was
successful.

@param[in] handle
    Handle of the recording session destruction operation of which to
    get the result.
@param[out] result
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*result} to
    the result of the recording session destruction operation identified
    by \lt_p{handle}.

    \lt_p{*result} is #LTTNG_OK if the destruction operation was
    successful.
    @endparblock

@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_OK
    Success: \lt_p{*result} is the result of the recording session
    destruction operation identified by \lt_p{handle}.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{handle}
    - You successfully waited for the completion of the recording session
      destruction operation identified by \lt_p{handle} with
      lttng_destruction_handle_wait_for_completion().
    @lt_pre_not_null{result}

@sa lttng_destruction_handle_wait_for_completion() --
    Waits for a recording session destruction operation to complete.
*/
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_result(const struct lttng_destruction_handle *handle,
				    enum lttng_error_code *result);

/*!
@brief
    Sets \lt_p{*rotation_state} to the state of a final
    \ref api_session_rotation "rotation" operation which the
    destruction of the recording session identified by \lt_p{handle}
    caused.

You must successfully wait for the completion of the recording session
destruction operation identified by \lt_p{handle} with
lttng_destruction_handle_wait_for_completion() before you call this
function.

This function is only useful if LTTng performed at least one recording
session rotation during the lifetime of the destroyed recording session.

@param[in] handle
    Handle of the destruction operation of the recording session of
    which to get the state of the final rotation operation.
@param[out] rotation_state
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*rotation_state} to the state of the final rotation operation
    which the recording session destruction operation identified by
    \lt_p{handle} caused.

    \lt_p{*rotation_state} is #LTTNG_ROTATION_STATE_NO_ROTATION if LTTng
    didn't perform any final recording session rotation.
    @endparblock

@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_OK
    Success: \lt_p{*rotation_state} is the state of the final rotation
    of the destroyed recording session.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{handle}
    - You successfully waited for the completion of the recording
      session destruction operation identified by \lt_p{handle} with
      lttng_destruction_handle_wait_for_completion().
    @lt_pre_not_null{rotation_state}

@sa lttng_destruction_handle_get_archive_location() --
    Get the location of the trace chunk archive which a recording
    session destruction operation created.
*/
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_rotation_state(const struct lttng_destruction_handle *handle,
					    enum lttng_rotation_state *rotation_state);

/*!
@brief
    Sets \lt_p{*location} to the
    \ref api_session_trace_archive_loc "location" of the final
    trace chunk archive which
    the destruction of the recording session identified by \lt_p{handle}
    created.

You must make sure that the destruction of the recording session caused
a final, successful rotation with
lttng_destruction_handle_get_rotation_state().

This function is only useful if LTTng performed at least one recording
session rotation during the lifetime of the destroyed recording session.

@param[in] handle
    Handle of the destruction operation of the recording session of
    which to get the location of the final trace chunk archive.
@param[out] location
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*location} to the location of the final trace chunk archive
    which the recording session destruction operation identified by
    \lt_p{handle} created.

    \lt_p{*location} is owned by \lt_p{handle}.
    @endparblock

@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_OK
    Success: \lt_p{*location} is the location of the final trace
    chunk archive of the destroyed recording session.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{handle}
    - lttng_destruction_handle_get_rotation_state() set the
      #LTTNG_ROTATION_STATE_COMPLETED state for \lt_p{handle}.
    @lt_pre_not_null{location}

@sa lttng_destruction_handle_get_rotation_state() --
    Get the state of the final rotation operation which a recording
    session destruction operation caused.
*/
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_archive_location(const struct lttng_destruction_handle *handle,
					      const struct lttng_trace_archive_location **location);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_DESTRUCTION_HANDLE_H */
