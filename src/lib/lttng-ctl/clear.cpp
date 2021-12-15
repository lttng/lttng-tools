/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2019 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <algorithm>
#include <string.h>

#include <lttng/lttng-error.h>
#include <lttng/clear.h>
#include <lttng/clear-handle.h>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/macros.hpp>
#include <common/compat/poll.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/buffer-view.hpp>
#include <common/optional.hpp>

#include "lttng-ctl-helper.hpp"

enum communication_state {
	COMMUNICATION_STATE_RECEIVE_LTTNG_MSG,
	COMMUNICATION_STATE_RECEIVE_COMMAND_HEADER,
	COMMUNICATION_STATE_END,
	COMMUNICATION_STATE_ERROR,
};

struct lttng_clear_handle {
	LTTNG_OPTIONAL(enum lttng_error_code) clear_return_code;
	struct {
		int socket;
		struct lttng_poll_event events;
		size_t bytes_left_to_receive;
		enum communication_state state;
		struct lttng_dynamic_buffer buffer;
		LTTNG_OPTIONAL(size_t) data_size;
	} communication;
};

void lttng_clear_handle_destroy(struct lttng_clear_handle *handle)
{
	int ret;

	if (!handle) {
		return;
	}

	if (handle->communication.socket >= 0) {
		ret = close(handle->communication.socket);
		if (ret) {
			PERROR("Failed to close lttng-sessiond command socket");
		}
	}
	lttng_poll_clean(&handle->communication.events);
	lttng_dynamic_buffer_reset(&handle->communication.buffer);
	free(handle);
}

static
struct lttng_clear_handle *lttng_clear_handle_create(int sessiond_socket)
{
	int ret;
	struct lttng_clear_handle *handle = (lttng_clear_handle *) zmalloc(sizeof(*handle));

	if (!handle) {
		goto end;
	}
	lttng_dynamic_buffer_init(&handle->communication.buffer);
	handle->communication.socket = sessiond_socket;
	ret = lttng_poll_create(&handle->communication.events, 1, 0);
	if (ret) {
		goto error;
	}

	ret = lttng_poll_add(&handle->communication.events, sessiond_socket,
			LPOLLIN | LPOLLHUP | LPOLLRDHUP | LPOLLERR);
	if (ret) {
		goto error;
	}

	handle->communication.bytes_left_to_receive =
			sizeof(struct lttcomm_lttng_msg);
	handle->communication.state = COMMUNICATION_STATE_RECEIVE_LTTNG_MSG;
end:
	return handle;
error:
	lttng_clear_handle_destroy(handle);
	return NULL;
}

static
int handle_state_transition(struct lttng_clear_handle *handle)
{
	int ret = 0;

	LTTNG_ASSERT(handle->communication.bytes_left_to_receive == 0);

	switch (handle->communication.state) {
	case COMMUNICATION_STATE_RECEIVE_LTTNG_MSG:
	{
		const struct lttcomm_lttng_msg *msg =
				(typeof(msg)) handle->communication.buffer.data;

		LTTNG_OPTIONAL_SET(&handle->clear_return_code,
				(enum lttng_error_code) msg->ret_code);
		if (handle->clear_return_code.value != LTTNG_OK) {
			handle->communication.state = COMMUNICATION_STATE_END;
			break;
		} else if (msg->cmd_header_size != 0 || msg->data_size != 0) {
			handle->communication.state = COMMUNICATION_STATE_ERROR;
			ret = -1;
			break;
		}

		handle->communication.state = COMMUNICATION_STATE_END;
		handle->communication.bytes_left_to_receive = 0;
		LTTNG_OPTIONAL_SET(&handle->communication.data_size, 0);
		ret = lttng_dynamic_buffer_set_size(
				&handle->communication.buffer, 0);
		LTTNG_ASSERT(!ret);
		break;
	}
	default:
		abort();
	}

	/* Clear reception buffer on state transition. */
	if (lttng_dynamic_buffer_set_size(&handle->communication.buffer, 0)) {
		abort();
	}
	return ret;
}

static
int handle_incoming_data(struct lttng_clear_handle *handle)
{
	int ret;
	ssize_t comm_ret;
	const size_t original_buffer_size = handle->communication.buffer.size;

	/* Reserve space for reception. */
	ret = lttng_dynamic_buffer_set_size(&handle->communication.buffer,
			original_buffer_size + handle->communication.bytes_left_to_receive);
	if (ret) {
		goto end;
	}

	comm_ret = lttcomm_recv_unix_sock(handle->communication.socket,
			handle->communication.buffer.data + original_buffer_size,
			handle->communication.bytes_left_to_receive);
	if (comm_ret <= 0) {
		ret = -1;
		goto end;
	}

	handle->communication.bytes_left_to_receive -= comm_ret;
	if (handle->communication.bytes_left_to_receive == 0) {
		ret = handle_state_transition(handle);
	} else {
		ret = lttng_dynamic_buffer_set_size(
				&handle->communication.buffer,
				original_buffer_size + comm_ret);
	}
end:
	return ret;
}

extern enum lttng_clear_handle_status
	lttng_clear_handle_wait_for_completion(
		struct lttng_clear_handle *handle, int timeout_ms)
{
	enum lttng_clear_handle_status status;
	unsigned long time_left_ms = 0;
	const bool has_timeout = timeout_ms > 0;
	struct timespec initial_time;

	if (handle->communication.state == COMMUNICATION_STATE_ERROR) {
		status = LTTNG_CLEAR_HANDLE_STATUS_ERROR;
		goto end;
	} else if (handle->communication.state == COMMUNICATION_STATE_END) {
		status = LTTNG_CLEAR_HANDLE_STATUS_COMPLETED;
		goto end;
	}
	if (has_timeout) {
		int ret = lttng_clock_gettime(CLOCK_MONOTONIC, &initial_time);
		if (ret) {
			status = LTTNG_CLEAR_HANDLE_STATUS_ERROR;
			goto end;
		}
		time_left_ms = (unsigned long) timeout_ms;
	}

	while (handle->communication.state != COMMUNICATION_STATE_END &&
			(time_left_ms || !has_timeout)) {
		int ret;
		uint32_t revents;
		struct timespec current_time, diff;
		unsigned long diff_ms;

		ret = lttng_poll_wait(&handle->communication.events,
				has_timeout ? time_left_ms : -1);
		if (ret == 0) {
			/* timeout */
			break;
		} else if (ret < 0) {
			status = LTTNG_CLEAR_HANDLE_STATUS_ERROR;
			goto end;
		}

		/* The sessiond connection socket is the only monitored fd. */
		revents = LTTNG_POLL_GETEV(&handle->communication.events, 0);
		if (revents & LPOLLIN) {
			ret = handle_incoming_data(handle);
			if (ret) {
				handle->communication.state =
						COMMUNICATION_STATE_ERROR;
				status = LTTNG_CLEAR_HANDLE_STATUS_ERROR;
				goto end;
			}
		} else {
			handle->communication.state = COMMUNICATION_STATE_ERROR;
			status = LTTNG_CLEAR_HANDLE_STATUS_ERROR;
			goto end;
		}
		if (!has_timeout) {
			continue;
		}

		ret = lttng_clock_gettime(CLOCK_MONOTONIC, &current_time);
		if (ret) {
			status = LTTNG_CLEAR_HANDLE_STATUS_ERROR;
			goto end;
		}
		diff = timespec_abs_diff(initial_time, current_time);
		ret = timespec_to_ms(diff, &diff_ms);
		if (ret) {
			ERR("Failed to compute elapsed time while waiting for completion");
			status = LTTNG_CLEAR_HANDLE_STATUS_ERROR;
			goto end;
		}
		DBG("%lums elapsed while waiting for session clear completion",
				diff_ms);
		diff_ms = std::max(diff_ms, 1UL);
		diff_ms = std::min(diff_ms, time_left_ms);
		time_left_ms -= diff_ms;
	}

	status = handle->communication.state == COMMUNICATION_STATE_END ?
			LTTNG_CLEAR_HANDLE_STATUS_COMPLETED :
			LTTNG_CLEAR_HANDLE_STATUS_TIMEOUT;
end:
	return status;
}

extern enum lttng_clear_handle_status
	lttng_clear_handle_get_result(
		const struct lttng_clear_handle *handle,
		enum lttng_error_code *result)
{
	enum lttng_clear_handle_status status =
			LTTNG_CLEAR_HANDLE_STATUS_OK;

	if (!handle->clear_return_code.is_set) {
		status = LTTNG_CLEAR_HANDLE_STATUS_INVALID;
		goto end;
	}
	*result = handle->clear_return_code.value;
end:
	return status;
}

/*
 * Clear the session
 */
enum lttng_error_code lttng_clear_session(const char *session_name,
		struct lttng_clear_handle **_handle)
{
	enum lttng_error_code ret_code = LTTNG_OK;
	struct lttng_clear_handle *handle = NULL;
	struct lttcomm_session_msg lsm = {
		.cmd_type = LTTNG_CLEAR_SESSION,
		.session = {},
		.domain = {},
		.u = {},
		.fd_count = 0,
	};
	int sessiond_socket = -1;
	ssize_t comm_ret;
	int ret;

	if (session_name == NULL) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}
	ret = lttng_strncpy(lsm.session.name, session_name,
			sizeof(lsm.session.name));
	if (ret) {
		ret_code = LTTNG_ERR_INVALID;
		goto error;
	}
	ret = connect_sessiond();
	if (ret < 0) {
		ret_code = LTTNG_ERR_NO_SESSIOND;
		goto error;
	} else {
		sessiond_socket = ret;
	}
	handle = lttng_clear_handle_create(sessiond_socket);
	if (!handle) {
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}
	comm_ret = lttcomm_send_creds_unix_sock(sessiond_socket, &lsm, sizeof(lsm));
	if (comm_ret < 0) {
		ret_code = LTTNG_ERR_FATAL;
		goto error;
	}
	sessiond_socket = -1;

error:
	/* Transfer the handle to the caller. */
	if (_handle) {
		*_handle = handle;
		handle = NULL;
	}
	if (sessiond_socket >= 0) {
		ret = close(sessiond_socket);
		if (ret < 0) {
			PERROR("Failed to close the LTTng session daemon connection socket");
		}
	}
	if (handle) {
		lttng_clear_handle_destroy(handle);
	}
	return ret_code;
}
