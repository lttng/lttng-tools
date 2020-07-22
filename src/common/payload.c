/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "payload.h"
#include <common/dynamic-array.h>
#include <common/dynamic-buffer.h>
#include <common/error.h>

LTTNG_HIDDEN
void lttng_payload_init(struct lttng_payload *payload)
{
	assert(payload);
	lttng_dynamic_buffer_init(&payload->buffer);
	lttng_dynamic_array_init(&payload->_fds, sizeof(int), NULL);
}

LTTNG_HIDDEN
int lttng_payload_copy(const struct lttng_payload *src_payload,
		       struct lttng_payload *dst_payload)
{
	int ret;
	size_t i;

	ret = lttng_dynamic_buffer_append_buffer(
			&dst_payload->buffer, &src_payload->buffer);
	if (ret) {
		goto error;
	}

	for (i = 0; i < lttng_dynamic_array_get_count(&src_payload->_fds);
			i++) {
		int dst_fd;
		const int src_fd = *((int *) lttng_dynamic_array_get_element(
					     &src_payload->_fds, i));

		dst_fd = dup(src_fd);
		if (dst_fd < 0) {
			PERROR("Failed to duplicate file descriptor while copying a payload");
			ret = dst_fd;
			goto error;
		}

		ret = lttng_payload_push_fd(dst_payload, dst_fd);
		if (ret) {
			const int close_ret = close(dst_fd);

			if (close_ret < 0) {
				PERROR("Failed to close duplicated file descriptor while copying a payload");
			}

			goto error;
		}
	}

end:
	return ret;
error:
	goto end;
}

LTTNG_HIDDEN
void lttng_payload_reset(struct lttng_payload *payload)
{
	if (!payload) {
		return;
	}

	lttng_dynamic_buffer_reset(&payload->buffer);
	lttng_dynamic_array_reset(&payload->_fds);
}

LTTNG_HIDDEN
int lttng_payload_push_fd(struct lttng_payload *payload, int fd)
{
	int ret;

	if (!payload) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_array_add_element(&payload->_fds, &fd);
end:
	return ret;
}
