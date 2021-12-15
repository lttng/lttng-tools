/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "payload.hpp"
#include <common/dynamic-array.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>

static
void release_fd_handle_ref(void *ptr)
{
	struct fd_handle *fd_handle = (struct fd_handle *) ptr;

	fd_handle_put(fd_handle);
}

void lttng_payload_init(struct lttng_payload *payload)
{
	LTTNG_ASSERT(payload);
	lttng_dynamic_buffer_init(&payload->buffer);
	lttng_dynamic_pointer_array_init(&payload->_fd_handles,
			release_fd_handle_ref);
}

int lttng_payload_copy(const struct lttng_payload *src_payload,
		       struct lttng_payload *dst_payload)
{
	int ret;
	size_t i;

	ret = lttng_dynamic_buffer_append_buffer(
			&dst_payload->buffer, &src_payload->buffer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < lttng_dynamic_pointer_array_get_count(
					&src_payload->_fd_handles);
			i++) {
		struct fd_handle *new_fd_handle;
		const struct fd_handle *src_fd_handle =
				(fd_handle *) lttng_dynamic_pointer_array_get_pointer(
						&src_payload->_fd_handles, i);

		new_fd_handle = fd_handle_copy(src_fd_handle);
		if (!new_fd_handle) {
			PERROR("Failed to copy fd_handle while copying a payload");
			ret = -1;
			goto end;
		}

		ret = lttng_payload_push_fd_handle(dst_payload, new_fd_handle);
		fd_handle_put(new_fd_handle);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

void lttng_payload_reset(struct lttng_payload *payload)
{
	if (!payload) {
		return;
	}

	lttng_dynamic_buffer_reset(&payload->buffer);
	lttng_dynamic_pointer_array_reset(&payload->_fd_handles);
}

void lttng_payload_clear(struct lttng_payload *payload)
{
	(void) lttng_dynamic_buffer_set_size(&payload->buffer, 0);
	lttng_dynamic_pointer_array_clear(&payload->_fd_handles);
}

int lttng_payload_push_fd_handle(struct lttng_payload *payload,
		struct fd_handle *fd_handle)
{
	int ret;

	if (!payload) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_pointer_array_add_pointer(
			&payload->_fd_handles, fd_handle);
	if (ret) {
		goto end;
	}

	fd_handle_get(fd_handle);
end:
	return ret;
}
