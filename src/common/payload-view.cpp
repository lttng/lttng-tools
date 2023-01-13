/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "payload-view.hpp"
#include "payload.hpp"

#include <common/buffer-view.hpp>
#include <common/dynamic-array.hpp>

#include <stddef.h>

bool lttng_payload_view_is_valid(const struct lttng_payload_view *view)
{
	return view && lttng_buffer_view_is_valid(&view->buffer);
}

struct lttng_payload_view
lttng_payload_view_from_payload(const struct lttng_payload *payload, size_t offset, ptrdiff_t len)
{
	return payload ?
		(struct lttng_payload_view){
			.buffer = lttng_buffer_view_from_dynamic_buffer(
				&payload->buffer, offset, len),
			._fd_handles = payload->_fd_handles,
			._iterator = {},
		} :
		(struct lttng_payload_view){
			.buffer = {},
			._fd_handles = {},
			._iterator = {},
		};
}

struct lttng_payload_view
lttng_payload_view_from_view(struct lttng_payload_view *view, size_t offset, ptrdiff_t len)
{
	return view ? (struct lttng_payload_view) {
		.buffer = lttng_buffer_view_from_view(
				&view->buffer, offset, len),
		._fd_handles = view->_fd_handles,
		._iterator = {
			.p_fd_handles_position = view->_iterator.p_fd_handles_position ?:
				&view->_iterator.fd_handles_position,
			.fd_handles_position = 0,
		}
	} : (struct lttng_payload_view) {
		.buffer = {},
		._fd_handles = {},
		._iterator = {},
	};
}

struct lttng_payload_view lttng_payload_view_from_dynamic_buffer(
	const struct lttng_dynamic_buffer *buffer, size_t offset, ptrdiff_t len)
{
	return buffer ?
		(struct lttng_payload_view){
			.buffer = lttng_buffer_view_from_dynamic_buffer(buffer, offset, len),
			._fd_handles = {},
			._iterator = {},
		} :
		(struct lttng_payload_view){
			.buffer = {},
			._fd_handles = {},
			._iterator = {},
		};
}

struct lttng_payload_view lttng_payload_view_from_buffer_view(const struct lttng_buffer_view *view,
							      size_t offset,
							      ptrdiff_t len)
{
	return view ?
		(struct lttng_payload_view){
			.buffer = lttng_buffer_view_from_view(view, offset, len),
			._fd_handles = {},
			._iterator = {},
		} :
		(struct lttng_payload_view){
			.buffer = {},
			._fd_handles = {},
			._iterator = {},
		};
}

struct lttng_payload_view
lttng_payload_view_init_from_buffer(const char *src, size_t offset, ptrdiff_t len)
{
	return (struct lttng_payload_view){
		.buffer = lttng_buffer_view_init(src, offset, len),
		._fd_handles = {},
		._iterator = {},
	};
}

int lttng_payload_view_get_fd_handle_count(const struct lttng_payload_view *payload_view)
{
	int ret;
	size_t position;

	if (!payload_view) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_pointer_array_get_count(&payload_view->_fd_handles);
	if (ret < 0) {
		goto end;
	}

	position = payload_view->_iterator.p_fd_handles_position ?
		*payload_view->_iterator.p_fd_handles_position :
		payload_view->_iterator.fd_handles_position;
	ret = ret - (int) position;
end:
	return ret;
}

struct fd_handle *lttng_payload_view_pop_fd_handle(struct lttng_payload_view *view)
{
	struct fd_handle *handle = nullptr;
	size_t fd_handle_count;
	size_t *pos;

	if (!view) {
		goto end;
	}

	fd_handle_count = lttng_payload_view_get_fd_handle_count(view);
	if (fd_handle_count == 0) {
		goto end;
	}

	pos = view->_iterator.p_fd_handles_position ? view->_iterator.p_fd_handles_position :
						      &view->_iterator.fd_handles_position;
	handle = (fd_handle *) lttng_dynamic_pointer_array_get_pointer(&view->_fd_handles, *pos);
	(*pos)++;
	fd_handle_get(handle);
end:
	return handle;
}
