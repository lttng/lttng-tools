/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "lttng-ctl-helper.hpp"

#include <common/macros.hpp>
#include <common/make-unique.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/stream-descriptor.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/reclaim-internal.hpp>
#include <lttng/reclaim.h>

#include <vendor/optional.hpp>

#include <string.h>

/*
 * The reclaim handle stores the result of a channel memory reclaim operation
 * and maintains the connection to the session daemon for async completion.
 *
 * After lttng_reclaim_channel_memory() returns successfully, the result
 * (reclaimed and pending byte counts) is immediately available via
 * lttng_reclaim_handle_get_reclaimed_memory_size_bytes() and
 * lttng_reclaim_handle_get_pending_memory_size_bytes().
 *
 * If there are pending bytes (sub-buffers awaiting consumption), users can
 * call lttng_reclaim_handle_wait_for_completion() to wait for all pending
 * reclamation to complete. The session daemon will send a completion
 * notification when all pending bytes have been reclaimed.
 *
 * The socket connection to the session daemon is kept open until the handle
 * is destroyed, allowing for async completion tracking.
 */
struct lttng_reclaim_handle {
	explicit lttng_reclaim_handle(lttng::stream_descriptor sessiond_socket) :
		socket(std::move(sessiond_socket))
	{
	}

	/* Result from the initial reclaim operation (immediately available). */
	lttng_reclaim_channel_memory_return result = {};

	/* Socket connection to session daemon for async completion. */
	lttng::stream_descriptor socket;

	/* Async completion status, unset if not received yet. */
	nonstd::optional<lttng_reclaim_handle_status> async_reclaim_status;
};

/*
 * Reclaim memory for a channel in a session.
 *
 * This function sends the reclaim command to the session daemon and waits
 * for the initial response, which contains:
 *   - The number of bytes reclaimed immediately
 *   - The number of bytes pending reclamation (awaiting consumption)
 *
 * On success, the handle is populated with the result and can be queried
 * immediately. The socket connection to the session daemon is kept open
 * in the handle to allow for async completion tracking.
 *
 * Return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK on success else a negative value.
 */
enum lttng_reclaim_channel_memory_status
lttng_reclaim_channel_memory(const char *session_name,
			     const char *channel_name,
			     enum lttng_domain_type domain,
			     uint64_t older_than_us,
			     struct lttng_reclaim_handle **handle)
{
	lttcomm_session_msg lsm = {};
	lttcomm_lttng_msg llm = {};
	lttng_reclaim_channel_memory_return reclaim_return = {};

	if (!session_name || !channel_name || !handle) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
	}

	const auto channel_name_len = strlen(channel_name);
	if (channel_name_len >= sizeof(lsm.u.reclaim_channel_memory.channel_name)) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
	}

	/* Setup session message. */
	lsm.cmd_type = LTTCOMM_SESSIOND_COMMAND_RECLAIM_CHANNEL_MEMORY;

	if (lttng_strncpy(lsm.session.name, session_name, sizeof(lsm.session.name))) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
	}

	lsm.domain.type = domain;

	/* Set channel name and max age. */
	if (lttng_strncpy(lsm.u.reclaim_channel_memory.channel_name,
			  channel_name,
			  sizeof(lsm.u.reclaim_channel_memory.channel_name))) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER;
	}

	lsm.u.reclaim_channel_memory.older_than_us = older_than_us;

	/* Connect to session daemon. Socket is managed by stream_descriptor (RAII). */
	const auto sessiond_socket_fd = connect_sessiond();
	if (sessiond_socket_fd < 0) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}

	lttng::stream_descriptor sessiond_socket(sessiond_socket_fd);

	/* Send command to session daemon. */
	auto comm_ret = lttcomm_send_creds_unix_sock(sessiond_socket.fd(), &lsm, sizeof(lsm));
	if (comm_ret < 0) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}

	/* Receive response header. */
	comm_ret = lttcomm_recv_unix_sock(sessiond_socket.fd(), &llm, sizeof(llm));
	if (comm_ret <= 0) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}

	/* Check return code. */
	if (llm.ret_code != LTTNG_OK) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}

	/* Validate expected payload size. */
	if (llm.data_size != sizeof(reclaim_return)) {
		ERR_FMT("Unexpected payload size from session daemon: expected_size={}, got={}",
			sizeof(reclaim_return),
			llm.data_size);
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}

	/* Receive payload. */
	comm_ret = lttcomm_recv_unix_sock(
		sessiond_socket.fd(), &reclaim_return, sizeof(reclaim_return));
	if (comm_ret <= 0) {
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}

	/* Create handle and transfer socket ownership. */
	try {
		auto _handle = new lttng_reclaim_handle(std::move(sessiond_socket));

		_handle->result.reclaimed_memory_size_bytes =
			reclaim_return.reclaimed_memory_size_bytes;
		_handle->result.pending_memory_size_bytes =
			reclaim_return.pending_memory_size_bytes;

		*handle = _handle;
	} catch (const std::exception& e) {
		ERR_FMT("Failed to allocate reclaim handle: {}", e.what());
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}

	return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK;
}

void lttng_reclaim_handle_destroy(lttng_reclaim_handle *handle)
{
	delete handle;
}

/*
 * Wait for the completion of pending memory reclamation.
 *
 * If there are no pending bytes (all memory was reclaimed immediately),
 * this function returns LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED right away.
 *
 * If there are pending bytes, this function waits for the session daemon
 * to send a completion notification indicating all pending sub-buffers
 * have been consumed and reclaimed.
 *
 * Note: As of this implementation, the backend is synchronous and all
 * reclamation completes immediately. This function is provided for API
 * completeness and will be extended in future commits to support true
 * asynchronous completion tracking.
 */
enum lttng_reclaim_handle_status
lttng_reclaim_handle_wait_for_completion(lttng_reclaim_handle *handle, int timeout_ms)
{
	if (!handle) {
		DBG_FMT("Invalid pre-condition: handle is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	/*
	 * Check if an async error was reported. If the optional has a value
	 * and it's not OK, an error occurred during async reclamation.
	 */
	if (handle->async_reclaim_status.has_value()) {
		return *handle->async_reclaim_status;
	}

	/*
	 * Currently, the backend is synchronous and completes immediately.
	 * When async completion tracking is implemented, this function will
	 * wait for a completion notification from the session daemon.
	 */
	(void) timeout_ms;

	return LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED;
}

lttng_reclaim_handle_status
lttng_reclaim_handle_get_reclaimed_memory_size_bytes(const lttng_reclaim_handle *handle,
						     uint64_t *memory_size_bytes)
{
	if (!handle) {
		DBG_FMT("Invalid pre-condition: handle is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	if (!memory_size_bytes) {
		DBG_FMT("Invalid pre-condition: memory_size_bytes is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	*memory_size_bytes = handle->result.reclaimed_memory_size_bytes;
	return LTTNG_RECLAIM_HANDLE_STATUS_OK;
}

lttng_reclaim_handle_status
lttng_reclaim_handle_get_pending_memory_size_bytes(const lttng_reclaim_handle *handle,
						   uint64_t *memory_size_bytes)
{
	if (!handle) {
		DBG_FMT("Invalid pre-condition: handle is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	if (!memory_size_bytes) {
		DBG_FMT("Invalid pre-condition: memory_size_bytes is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	*memory_size_bytes = handle->result.pending_memory_size_bytes;
	return LTTNG_RECLAIM_HANDLE_STATUS_OK;
}
