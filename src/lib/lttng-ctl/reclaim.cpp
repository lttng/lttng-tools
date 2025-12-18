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
#include <common/poller.hpp>
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
 * (reclaimed and pending sub-buffer counts) is immediately available via
 * lttng_reclaim_handle_get_reclaimed_subbuffer_count() and
 * lttng_reclaim_handle_get_pending_subbuffer_count().
 *
 * If there are pending sub-buffers (awaiting consumption), users can
 * call lttng_reclaim_handle_wait_for_completion() to wait for all pending
 * reclamation to complete. The session daemon will send a completion
 * notification when all pending sub-buffers have been reclaimed.
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

namespace {
lttng_reclaim_channel_memory_status lttng_error_code_to_reclaim_status(lttng_error_code error_code)
{
	switch (error_code) {
	case LTTNG_OK:
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK;
	case LTTNG_ERR_SESS_NOT_FOUND:
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_SESSION_NOT_FOUND;
	case LTTNG_ERR_CHAN_NOT_FOUND:
	case LTTNG_ERR_UST_CHAN_NOT_FOUND:
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_CHANNEL_NOT_FOUND;
	case LTTNG_ERR_NOT_SUPPORTED:
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_NOT_SUPPORTED;
	case LTTNG_ERR_ROTATION_PENDING:
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_RECLAMATION_IN_PROGRESS;
	default:
		return LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR;
	}
}
} /* namespace */

enum lttng_reclaim_channel_memory_status
lttng_reclaim_channel_memory(const char *session_name,
			     const char *channel_name,
			     enum lttng_domain_type domain,
			     uint64_t older_than_age_us,
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

	lsm.u.reclaim_channel_memory.older_than_age_us = older_than_age_us;

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
		return lttng_error_code_to_reclaim_status(
			static_cast<lttng_error_code>(llm.ret_code));
	}

	/* Validate expected payload size. */
	if (llm.data_size != sizeof(reclaim_return)) {
		/* Packed fields can't be bound to references; copy to local. */
		const auto data_size = llm.data_size;
		ERR_FMT("Unexpected payload size from session daemon: expected={}, got={}",
			sizeof(reclaim_return),
			data_size);
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

		_handle->result = reclaim_return;
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

enum lttng_reclaim_handle_status
lttng_reclaim_handle_wait_for_completion(lttng_reclaim_handle *handle, int timeout_ms)
{
	if (!handle) {
		DBG_FMT("Invalid pre-condition: handle is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	/*
	 * Check if we already received the async status (from a previous call
	 * or if it was set during initial processing).
	 */
	if (handle->async_reclaim_status.has_value()) {
		return *handle->async_reclaim_status;
	}

	/*
	 * If there are no pending sub-buffers, the reclamation completed immediately
	 * and there's nothing to wait for.
	 */
	if (handle->result.pending_subbuffer_count == 0) {
		handle->async_reclaim_status = LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED;
		return LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED;
	}

	/*
	 * Wait for the session daemon to send a completion status.
	 * The session daemon sends an lttcomm_lttng_msg with ret_code and data_size=0.
	 */
	lttng::poller waiter;
	bool socket_readable = false;
	bool socket_error = false;

	waiter.add(handle->socket,
		   lttng::poller::event_type::READABLE | lttng::poller::event_type::ERROR |
			   lttng::poller::event_type::CLOSED,
		   [&socket_readable, &socket_error](lttng::poller::event_type events) {
			   socket_readable = (events & lttng::poller::event_type::READABLE) !=
				   lttng::poller::event_type::NONE;

			   socket_error = (events &
					   (lttng::poller::event_type::ERROR |
					    lttng::poller::event_type::CLOSED)) !=
				   lttng::poller::event_type::NONE;
		   });

	try {
		if (timeout_ms < 0) {
			waiter.poll(lttng::poller::timeout_type::WAIT_FOREVER);
		} else if (timeout_ms == 0) {
			waiter.poll(lttng::poller::timeout_type::NO_WAIT);
		} else {
			waiter.poll(lttng::poller::timeout_ms(timeout_ms));
		}
	} catch (const std::exception& e) {
		ERR_FMT("Failed to poll on reclaim handle socket: {}", e.what());
		handle->async_reclaim_status = LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
		return LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
	}

	if (socket_error && !socket_readable) {
		DBG("Socket error while waiting for reclaim completion");
		handle->async_reclaim_status = LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
		return LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
	}

	if (!socket_readable) {
		/* Timeout; status not yet available. */
		return LTTNG_RECLAIM_HANDLE_STATUS_TIMEOUT;
	}

	/* Read the async completion message. */
	lttng_reclaim_channel_memory_async_completion completion = {};
	const auto recv_ret =
		lttcomm_recv_unix_sock(handle->socket.fd(), &completion, sizeof(completion));
	if (recv_ret <= 0) {
		ERR_FMT("Failed to receive reclaim async completion: recv_ret={}", recv_ret);
		handle->async_reclaim_status = LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
		return LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
	}

	/* Check the status code. */
	if (completion.status != LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK) {
		DBG_FMT("Reclaim async completion returned error: status={}", completion.status);
		handle->async_reclaim_status = LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
		return LTTNG_RECLAIM_HANDLE_STATUS_ERROR;
	}

	handle->async_reclaim_status = LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED;
	return LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED;
}

lttng_reclaim_handle_status
lttng_reclaim_handle_get_reclaimed_subbuffer_count(const lttng_reclaim_handle *handle,
						   uint64_t *count)
{
	if (!handle) {
		DBG_FMT("Invalid pre-condition: handle is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	if (!count) {
		DBG_FMT("Invalid pre-condition: count is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	*count = handle->result.reclaimed_subbuffer_count;
	return LTTNG_RECLAIM_HANDLE_STATUS_OK;
}

lttng_reclaim_handle_status
lttng_reclaim_handle_get_pending_subbuffer_count(const lttng_reclaim_handle *handle,
						 uint64_t *count)
{
	if (!handle) {
		DBG_FMT("Invalid pre-condition: handle is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	if (!count) {
		DBG_FMT("Invalid pre-condition: count is null");
		return LTTNG_RECLAIM_HANDLE_STATUS_INVALID;
	}

	*count = handle->result.pending_subbuffer_count;
	return LTTNG_RECLAIM_HANDLE_STATUS_OK;
}
