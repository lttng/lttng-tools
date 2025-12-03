/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RECLAIM_H
#define LTTNG_RECLAIM_H

#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_channel_reclaim
@{
*/

/*!
@struct lttng_reclaim_handle

@brief
    \lt_obj_c_channel memory reclaim operation handle (opaque type).
*/
struct lttng_reclaim_handle;

/*!
@brief
    Return type of lttng_reclaim_channel_memory().

Error status enumerators have a negative value.
*/
enum lttng_reclaim_channel_memory_status {
	/// Success.
	LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK = 0,

	/// Error.
	LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR = -1,

	/// Unsatisfied precondition.
	LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER = -2,
};

/*!
@brief
    Return type of \lt_obj_channel memory reclaim handle functions.

Error status enumerators have a negative value.
*/
enum lttng_reclaim_handle_status {
	/// Success.
	LTTNG_RECLAIM_HANDLE_STATUS_OK = 0,

	/// Reclamation operation completed.
	LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED = 1,

	/// Timeout reached.
	LTTNG_RECLAIM_HANDLE_STATUS_TIMEOUT = 2,

	/// Unsatisfied precondition.
	LTTNG_RECLAIM_HANDLE_STATUS_INVALID = -1,

	/// Other error.
	LTTNG_RECLAIM_HANDLE_STATUS_ERROR = -2,
};

/*!
@brief
    Initiates an immediate memory reclaim operation for
    the \lt_obj_channel named \lt_p{channel_name} within the
    \lt_obj_session named \lt_p{session_name} and the
    tracing domain \lt_p{domain}.

This function requests LTTng to immediately reclaim memory which the
buffers of the targeted channel use in order to free space.

This function only works with a user space channel.

Use \lt_p{*handle} to wait for the completion of the memory reclaim
operation and to fetch its result.

@param[in] session_name
    Name of the recording session which contains the targeted channel.
@param[in] channel_name
    Name of the targeted channel within \lt_p{session_name} from which
    to reclaim memory.
@param[in] domain
    Tracing domain of the targeted channel.
@param[in] older_than_us
    @parblock
    Minimum age (µs) of buffered data to consider to reclaim memory.

    Set to 0 for no age constraint.
    @endparblock
@param[out] handle
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*handle} to a
    handle identifying this memory reclaim operation.

    May be \c NULL.

    Wait for the completion of this operation with
    lttng_reclaim_handle_wait_for_completion().

    Destroy \lt_p{*handle} with lttng_reclaim_handle_destroy().
    @endparblock

@retval #LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK
    Success.
@retval #LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR
    Error.
@retval #LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
    @lt_pre_not_null{channel_name}
    - \lt_p{domain} is #LTTNG_DOMAIN_UST, #LTTNG_DOMAIN_JUL,
      #LTTNG_DOMAIN_LOG4J, #LTTNG_DOMAIN_LOG4J2, or
      #LTTNG_DOMAIN_PYTHON.
*/
LTTNG_EXPORT extern enum lttng_reclaim_channel_memory_status
lttng_reclaim_channel_memory(const char *session_name,
			     const char *channel_name,
			     enum lttng_domain_type domain,
			     uint64_t older_than_us,
			     struct lttng_reclaim_handle **handle);

/*!
@brief
    Destroys the channel memory reclaim operation handle \lt_p{handle}.

@param[in] handle
    @parblock
    Channel memory reclaim operation handle to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_reclaim_handle_destroy(struct lttng_reclaim_handle *handle);

/*!
@brief
    Waits for the channel memory reclaim operation identified by
    \lt_p{handle} to complete.

If this function returns #LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED, then
the memory reclaim operation identified by \lt_p{handle} completed. This
does not indicate whether the memory reclaim operation itself succeeded;
use lttng_reclaim_handle_get_reclaimed_memory_size_bytes() to get
the reclaimed amount.

@param[in] handle
    Channel memory reclaim operation handle of which to wait for
    completion.
@param[in] timeout_ms
    Maximum time (milliseconds) to wait for the completion of the
    memory reclaim operation identified by \lt_p{handle} before returning
    #LTTNG_RECLAIM_HANDLE_STATUS_TIMEOUT, or <code>-1</code> to wait
    indefinitely.

@retval #LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED
    The memory reclaim operation identified by \lt_p{handle} completed
    (with or without success).
@retval #LTTNG_RECLAIM_HANDLE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_RECLAIM_HANDLE_STATUS_TIMEOUT
    The function waited for the completion of the memory reclaim
    operation more than \lt_p{timeout_ms}&nbsp;ms.
@retval #LTTNG_RECLAIM_HANDLE_STATUS_ERROR
    Other error.

@pre
    @lt_pre_not_null{handle}

@sa lttng_reclaim_handle_get_reclaimed_memory_size_bytes() --
    Returns the number of bytes reclaimed.
*/
LTTNG_EXPORT extern enum lttng_reclaim_handle_status
lttng_reclaim_handle_wait_for_completion(struct lttng_reclaim_handle *handle, int timeout_ms);

/*!
@brief
    Sets \lt_p{*memory_size_bytes} to the total number of bytes
    successfully reclaimed by the channel memory reclaim operation
    identified by \lt_p{handle}.

The reclaimed memory size is available immediately after
lttng_reclaim_channel_memory() returns successfully.

@param[in] handle
    Handle of the channel memory reclaim operation from which to get
    the number of reclaimed bytes.
@param[out] memory_size_bytes
    <strong>On success</strong>, this function sets
    \lt_p{*memory_size_bytes} to the number of bytes successfully
    reclaimed.

@retval #LTTNG_RECLAIM_HANDLE_STATUS_OK
    Success.
@retval #LTTNG_RECLAIM_HANDLE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{handle}
    @lt_pre_not_null{memory_size_bytes}
*/
LTTNG_EXPORT extern enum lttng_reclaim_handle_status
lttng_reclaim_handle_get_reclaimed_memory_size_bytes(const struct lttng_reclaim_handle *handle,
						     uint64_t *memory_size_bytes);

/*!
@brief
    Sets \lt_p{*memory_size_bytes} to the total number of bytes
    pending reclamation from the channel memory reclaim operation
    identified by \lt_p{handle}.

Pending bytes are sub-buffers that met the reclamation criteria but
could not be immediately reclaimed because their data has not yet been
consumed. These sub-buffers will be automatically reclaimed as they
are consumed.

The pending memory size is available immediately after
lttng_reclaim_channel_memory() returns successfully.

@param[in] handle
    Handle of the channel memory reclaim operation from which to get
    the number of pending bytes.
@param[out] memory_size_bytes
    <strong>On success</strong>, this function sets
    \lt_p{*memory_size_bytes} to the number of bytes pending
    reclamation.

@retval #LTTNG_RECLAIM_HANDLE_STATUS_OK
    Success.
@retval #LTTNG_RECLAIM_HANDLE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{handle}
    @lt_pre_not_null{memory_size_bytes}
*/
LTTNG_EXPORT extern enum lttng_reclaim_handle_status
lttng_reclaim_handle_get_pending_memory_size_bytes(const struct lttng_reclaim_handle *handle,
						   uint64_t *memory_size_bytes);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_RECLAIM_H */
