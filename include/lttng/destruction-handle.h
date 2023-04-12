/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

/*
 * Handle used to represent a specific instance of session destruction
 * operation.
 *
 * See lttng_destroy_session_ext() in lttng/session.h.
 */
struct lttng_destruction_handle;

/*
 * Negative values indicate errors. Values >= 0 indicate success.
 */
enum lttng_destruction_handle_status {
	/* Generic error. */
	LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR = -2,
	/* Invalid parameters provided */
	LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID = -1,
	/* Success. */
	LTTNG_DESTRUCTION_HANDLE_STATUS_OK = 0,
	/* Destruction operation completed successfully. */
	LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED = 1,
	/* Operation timed out. */
	LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT = 2,
};

/*
 * Destroy an lttng_destruction_session handle.
 * The handle should be discarded after this call.
 */
LTTNG_EXPORT extern void lttng_destruction_handle_destroy(struct lttng_destruction_handle *handle);

/*
 * Wait for the destruction of a session to complete.
 *
 * A negative timeout_ms value can be used to wait indefinitely.
 *
 * Returns LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED if the session destruction
 * operation was completed. LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT is returned
 * to indicate that the wait timed out.
 * On error, one of the negative lttng_destruction_handle_status is returned.
 *
 * Note: This function returning a success status does not mean that
 * the destruction operation itself succeeded; it indicates that the _wait_
 * operation completed successfully.
 */
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_wait_for_completion(struct lttng_destruction_handle *handle,
					     int timeout_ms);

/*
 * Get the result of a session destruction operation.
 *
 * This function must be used on a session destruction handle which was
 * successfully waited on.
 *
 * Returns LTTNG_DESTRUCTION_HANDLE_STATUS_OK if the result of the session
 * destruction operation could be obtained. Check the value of 'result' to
 * determine if the destruction of the session completed successfully or not.
 *
 * On error, one of the negative lttng_destruction_handle_status is returned.
 * Returns LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID if the session destruction
 * was not waited-on using the handle or if the arguments of the function are
 * invalid (e.g. NULL).
 */
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_result(const struct lttng_destruction_handle *handle,
				    enum lttng_error_code *result);

/*
 * Get the status of the session rotation performed as part of the session's
 * destruction.
 *
 * A session will perform a final rotation if it was ever rotated over its
 * lifetime. If this happens, this function returns the state of the rotation
 * that was performed.
 *
 * This function must be used on a session destruction handle which was
 * successfully waited on.
 *
 * Returns LTTNG_DESTRUCTION_HANDLE_STATUS_OK if the state of the session
 * rotation could be obtained. Check the value of 'rotation_state' to
 * determine if the rotation of the session completed successfully or not.
 *
 * On error, one of the negative lttng_destruction_handle_status is returned.
 * Returns LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID if the session destruction
 * was not waited-on using the handle or if the arguments of the function are
 * invalid (e.g. NULL).
 *
 * Note that if no rotation was performed, rotation_state will be set to
 * LTTNG_ROTATION_STATE_NO_ROTATION.
 */
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_rotation_state(const struct lttng_destruction_handle *handle,
					    enum lttng_rotation_state *rotation_state);

/*
 * Get the location of the archive resulting from the rotation performed during
 * the session's destruction.
 *
 * This function must be used on a session destruction handle which was
 * successfully waited on and a session rotation must have been be completed
 * successfully in order for this call to succeed.
 *
 * The location returned remains owned by the session destruction handle.
 *
 * Returns LTTNG_DESTRUCTION_HANDLE_STATUS_OK if the location of the archive
 * resulting from the session rotation could be obtained.
 *
 * On error, one of the negative lttng_destruction_handle_status is returned.
 * Returns LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID if the session destruction
 * was not waited-on using the handle, if no session rotation occurred as part
 * of the session's destruction, or if the arguments of the function are
 * invalid (e.g. NULL).
 */
LTTNG_EXPORT extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_archive_location(const struct lttng_destruction_handle *handle,
					      const struct lttng_trace_archive_location **location);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_DESTRUCTION_HANDLE_H */
