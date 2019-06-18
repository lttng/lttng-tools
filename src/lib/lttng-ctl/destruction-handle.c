/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <lttng/destruction-handle.h>
#include <lttng/rotation.h>

#include <common/optional.h>
#include <common/compat/poll.h>
#include <common/compat/time.h>
#include <common/macros.h>
#include <common/compat/poll.h>
#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <lttng/location-internal.h>
#include "lttng-ctl-helper.h"

#include <stdbool.h>

enum communication_state {
	COMMUNICATION_STATE_RECEIVE_LTTNG_MSG,
	COMMUNICATION_STATE_RECEIVE_COMMAND_HEADER,
	COMMUNICATION_STATE_RECEIVE_PAYLOAD,
	COMMUNICATION_STATE_END,
	COMMUNICATION_STATE_ERROR,
};

struct lttng_destruction_handle {
	LTTNG_OPTIONAL(enum lttng_error_code) destruction_return_code;
	LTTNG_OPTIONAL(enum lttng_rotation_state) rotation_state;
	struct lttng_trace_archive_location *location;
	struct {
		int socket;
		struct lttng_poll_event events;
		size_t bytes_left_to_receive;
		enum communication_state state;
		struct lttng_dynamic_buffer buffer;
		LTTNG_OPTIONAL(size_t) data_size;
	} communication;
};

void lttng_destruction_handle_destroy(struct lttng_destruction_handle *handle)
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
	lttng_trace_archive_location_destroy(handle->location);
	free(handle);
}

static
struct lttng_destruction_handle *lttng_destruction_handle_create(
		int sessiond_socket)
{
	int ret;
	struct lttng_destruction_handle *handle = zmalloc(sizeof(*handle));

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
	lttng_destruction_handle_destroy(handle);
	return NULL;
}

static
int handle_state_transition(struct lttng_destruction_handle *handle)
{
	int ret = 0;

	assert(handle->communication.bytes_left_to_receive == 0);

	switch (handle->communication.state) {
	case COMMUNICATION_STATE_RECEIVE_LTTNG_MSG:
	{
		const struct lttcomm_lttng_msg *msg =
				(typeof(msg)) handle->communication.buffer.data;

		LTTNG_OPTIONAL_SET(&handle->destruction_return_code,
				(enum lttng_error_code) msg->ret_code);
		if (handle->destruction_return_code.value != LTTNG_OK) {
			handle->communication.state = COMMUNICATION_STATE_END;
			break;
		} else if (msg->cmd_header_size != sizeof(struct lttcomm_session_destroy_command_header) ||
				msg->data_size > DEFAULT_MAX_TRACE_ARCHIVE_LOCATION_PAYLOAD_SIZE) {
			handle->communication.state = COMMUNICATION_STATE_ERROR;
			ret = -1;
			break;
		}

		handle->communication.state =
				COMMUNICATION_STATE_RECEIVE_COMMAND_HEADER;
		handle->communication.bytes_left_to_receive =
				msg->cmd_header_size;
		LTTNG_OPTIONAL_SET(&handle->communication.data_size,
				msg->data_size);
		ret = lttng_dynamic_buffer_set_size(
				&handle->communication.buffer, 0);
		assert(!ret);
		break;
	}
	case COMMUNICATION_STATE_RECEIVE_COMMAND_HEADER:
	{
		const struct lttcomm_session_destroy_command_header *hdr =
				(typeof(hdr)) handle->communication.buffer.data;

		LTTNG_OPTIONAL_SET(&handle->rotation_state,
				(enum lttng_rotation_state) hdr->rotation_state);
		switch (handle->rotation_state.value) {
		case LTTNG_ROTATION_STATE_COMPLETED:
			handle->communication.state =
					COMMUNICATION_STATE_RECEIVE_PAYLOAD;
			handle->communication.bytes_left_to_receive =
					LTTNG_OPTIONAL_GET(handle->communication.data_size);
			break;
		case LTTNG_ROTATION_STATE_ERROR:
		case LTTNG_ROTATION_STATE_NO_ROTATION:
			handle->communication.state = COMMUNICATION_STATE_END;
			break;
		default:
			handle->communication.state = COMMUNICATION_STATE_ERROR;
			ret = -1;
			break;
		}
		break;
	}
	case COMMUNICATION_STATE_RECEIVE_PAYLOAD:
	{
		ssize_t location_ret;
		struct lttng_trace_archive_location *location;
		const struct lttng_buffer_view view =
				lttng_buffer_view_from_dynamic_buffer(
					&handle->communication.buffer, 0, -1);

		location_ret = lttng_trace_archive_location_create_from_buffer(
				&view, &location);
		if (location_ret < 0) {
			ERR("Failed to deserialize trace archive location");
			handle->communication.state = COMMUNICATION_STATE_ERROR;
			ret = -1;
			break;
		} else {
			handle->location = location;
			handle->communication.state = COMMUNICATION_STATE_END;
		}
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
int handle_incoming_data(struct lttng_destruction_handle *handle)
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

enum lttng_destruction_handle_status
lttng_destruction_handle_wait_for_completion(
		struct lttng_destruction_handle *handle, int timeout_ms)
{
	int ret;
	enum lttng_destruction_handle_status status;
	unsigned long time_left_ms = 0;
	const bool has_timeout = timeout_ms > 0;
        struct timespec initial_time;

        if (handle->communication.state == COMMUNICATION_STATE_ERROR) {
		status = LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR;
		goto end;
	} else if (handle->communication.state == COMMUNICATION_STATE_END) {
		status = LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED;
		goto end;
	}
        if (has_timeout) {
		ret = lttng_clock_gettime(CLOCK_MONOTONIC, &initial_time);
		if (ret) {
			status = LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR;
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
			status = LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR;
			goto end;
		}

		/* The sessiond connection socket is the only monitored fd. */
		revents = LTTNG_POLL_GETEV(&handle->communication.events, 0);
		if (revents & LPOLLIN) {
			ret = handle_incoming_data(handle);
			if (ret) {
				handle->communication.state =
						COMMUNICATION_STATE_ERROR;
				status = LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR;
				goto end;
			}
		} else {
			handle->communication.state = COMMUNICATION_STATE_ERROR;
			status = LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR;
			goto end;
		}
		if (!has_timeout) {
			continue;
		}

		ret = lttng_clock_gettime(CLOCK_MONOTONIC, &current_time);
		if (ret) {
			status = LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR;
			goto end;
		}
		diff = timespec_abs_diff(initial_time, current_time);
		ret = timespec_to_ms(diff, &diff_ms);
		if (ret) {
			ERR("Failed to compute elapsed time while waiting for completion");
			status = LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR;
			goto end;
		}
		DBG("%lums elapsed while waiting for session destruction completion",
				diff_ms);
		diff_ms = max_t(unsigned long, diff_ms, 1);
		diff_ms = min_t(unsigned long, diff_ms, time_left_ms);
		time_left_ms -= diff_ms;
	}

	status = handle->communication.state == COMMUNICATION_STATE_END ?
			LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED :
			LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT;
end:
	return status;
}

enum lttng_destruction_handle_status
lttng_destruction_handle_get_rotation_state(
		const struct lttng_destruction_handle *handle,
		enum lttng_rotation_state *rotation_state)
{
	enum lttng_destruction_handle_status status =
			LTTNG_DESTRUCTION_HANDLE_STATUS_OK;

	if (!handle->rotation_state.is_set) {
		status = LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID;
		goto end;
	}
	*rotation_state = handle->rotation_state.value;
end:
	return status;
}

enum lttng_destruction_handle_status
lttng_destruction_handle_get_archive_location(
		const struct lttng_destruction_handle *handle,
		const struct lttng_trace_archive_location **location)
{
	enum lttng_destruction_handle_status status =
			LTTNG_DESTRUCTION_HANDLE_STATUS_OK;

	if (!handle->location) {
		status = LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID;
		goto end;
	}
	*location = handle->location;
end:
	return status;
}

enum lttng_destruction_handle_status
lttng_destruction_handle_get_result(
		const struct lttng_destruction_handle *handle,
		enum lttng_error_code *result)
{
	enum lttng_destruction_handle_status status =
			LTTNG_DESTRUCTION_HANDLE_STATUS_OK;

	if (!handle->destruction_return_code.is_set) {
		status = LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID;
		goto end;
	}
	*result = handle->destruction_return_code.value;
end:
	return status;
}

enum lttng_error_code lttng_destroy_session_ext(const char *session_name,
		struct lttng_destruction_handle **_handle)
{
	int ret;
	ssize_t comm_ret;
	enum lttng_error_code ret_code = LTTNG_OK;
        struct lttcomm_session_msg lsm = {
		.cmd_type = LTTNG_DESTROY_SESSION,
	};
	int sessiond_socket = -1;
	struct lttng_destruction_handle *handle = NULL;

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

	handle = lttng_destruction_handle_create(sessiond_socket);
	if (!handle) {
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}

	comm_ret = lttcomm_send_unix_sock(sessiond_socket, &lsm, sizeof(lsm));
	if (comm_ret < 0) {
		ret_code = LTTNG_ERR_FATAL;
		goto error;
	}
	sessiond_socket = -1;

	/* Transfer the handle to the caller. */
	if (_handle) {
		*_handle = handle;
		handle = NULL;
	}
error:
	if (sessiond_socket >= 0) {
		ret = close(sessiond_socket);
		PERROR("Failed to close the LTTng session daemon connection socket");
	}
	if (handle) {
		lttng_destruction_handle_destroy(handle);
	}
	return ret_code;
}
