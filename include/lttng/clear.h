/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CLEAR_H
#define LTTNG_CLEAR_H

#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_clear_handle;

/*
 * Clear a tracing session.
 *
 * Clear the data buffers and trace data.
 *
 * For sessions saving trace data to disk and streaming over the network to a
 * relay daemon, the buffers content and existing stream files are cleared when
 * the clear command is issued.
 *
 * For snapshot sessions (flight recorder), only the buffer content is cleared.
 * Prior snapshots are individually recorded to disk, and are therefore
 * untouched by this "clear" command.
 *
 * For live sessions streaming over network to a relay daemon, the buffers
 * will be cleared and the files on the relay daemon side will be cleared as
 * well. However, any active live trace viewer currently reading an existing
 * trace packet will be able to proceed to read that packet entirely before
 * skipping over cleared stream data.
 *
 * The clear command guarantees that no trace data produced before this function
 * is called will be present in the resulting trace.
 *
 * Trace data produced between the moment this function is called and when it
 * returns might be present in the resulting trace.
 *
 * Provides an lttng_clear_handle which can be used to wait for the completion
 * of the session's clear.
 *
 * Return LTTNG_OK on success else a negative LTTng error code. The returned
 * handle is owned by the caller and must be free'd using
 * lttng_clear_handle_destroy().
 *
 * Important error codes:
 *    LTTNG_ERR_CLEAR_RELAY_DISALLOWED
 *    LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY
 *    LTTNG_ERR_CLEAR_FAIL_CONSUMER
 */
LTTNG_EXPORT extern enum lttng_error_code lttng_clear_session(const char *session_name,
							      struct lttng_clear_handle **handle);
#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CLEAR_H */
