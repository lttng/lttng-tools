/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

/*
 * Handle used to represent a specific instance of session clear
 * operation.
 */
struct lttng_clear_handle;

/*
 * Negative values indicate errors. Values >= 0 indicate success.
 */
enum lttng_clear_handle_status {
	LTTNG_CLEAR_HANDLE_STATUS_ERROR = -2,
	LTTNG_CLEAR_HANDLE_STATUS_INVALID = -1,
	LTTNG_CLEAR_HANDLE_STATUS_OK = 0,
	LTTNG_CLEAR_HANDLE_STATUS_COMPLETED = 1,
	LTTNG_CLEAR_HANDLE_STATUS_TIMEOUT = 2,
};

/*
 * Destroy an lttng_clear_handle.
 * The handle should be discarded after this call.
 */
LTTNG_EXPORT extern void lttng_clear_handle_destroy(struct lttng_clear_handle *handle);

/*
 * Wait for a session clear operation to complete.
 *
 * A negative timeout_ms value can be used to wait indefinitely.
 *
 * Returns LTTNG_CLEAR_HANDLE_STATUS_COMPLETED if the session clear
 * operation was completed. LTTNG_CLEAR_HANDLE_STATUS_TIMEOUT is returned
 * to indicate that the wait timed out.
 * On error, one of the negative lttng_clear_handle_status is returned.
 *
 * Note: This function returning a success status does not mean that
 * the clear operation itself succeeded; it indicates that the _wait_
 * operation completed successfully.
 */
LTTNG_EXPORT extern enum lttng_clear_handle_status
lttng_clear_handle_wait_for_completion(struct lttng_clear_handle *handle, int timeout_ms);

/*
 * Get the result of a session clear operation.
 *
 * This function must be used on a clear handle which was successfully waited
 * on.
 *
 * Returns LTTNG_CLEAR_HANDLE_STATUS_OK if the result of the session
 * clear operation could be obtained. Check the value of 'result' to
 * determine if the session clear operation completed successfully or not.
 *
 * On error, one of the negative lttng_clear_handle_status is returned.
 * Returns LTTNG_CLEAR_HANDLE_STATUS_INVALID if the clear operation
 * was not waited-on using the handle or if the arguments of the function are
 * invalid (e.g. NULL).
 */
LTTNG_EXPORT extern enum lttng_clear_handle_status
lttng_clear_handle_get_result(const struct lttng_clear_handle *handle,
			      enum lttng_error_code *result);
#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CLEAR_HANDLE_H */
