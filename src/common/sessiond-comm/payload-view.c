/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/buffer-view.h>
#include "payload-view.h"
#include "payload.h"
#include <stddef.h>

LTTNG_HIDDEN
struct lttng_payload_view lttng_payload_view_from_payload(
		const struct lttng_payload *payload, size_t offset,
		ptrdiff_t len)
{
	return (struct lttng_payload_view) {
		.buffer = lttng_buffer_view_from_dynamic_buffer(
			&payload->buffer, offset, len),
		._fds = payload->_fds,
	};
}

LTTNG_HIDDEN
struct lttng_payload_view lttng_payload_view_from_view(
		struct lttng_payload_view *view, size_t offset,
		ptrdiff_t len)
{
	return (struct lttng_payload_view) {
		.buffer = lttng_buffer_view_from_view(
			&view->buffer, offset, len),
		._fds = view->_fds,
		._iterator.p_fds_position = &view->_iterator.fds_position,
	};
}

LTTNG_HIDDEN
struct lttng_payload_view lttng_payload_view_from_dynamic_buffer(
		const struct lttng_dynamic_buffer *buffer, size_t offset,
		ptrdiff_t len)
{
	return (struct lttng_payload_view) {
		.buffer = lttng_buffer_view_from_dynamic_buffer(
			buffer, offset, len)
	};
}

LTTNG_HIDDEN
int lttng_payload_view_pop_fd(struct lttng_payload_view *view)
{
	int ret = 0;
	size_t fd_count;
	size_t *pos;

	if (!view) {
		ret = -1;
		goto end;
	}

	fd_count = lttng_dynamic_array_get_count(&view->_fds);
	pos = view->_iterator.p_fds_position ? view->_iterator.p_fds_position :
		&view->_iterator.fds_position;

	if (*pos >= fd_count) {
		ret = -1;
		goto end;
	}

	ret = *((int *) lttng_dynamic_array_get_element(
			&view->_fds, *pos));
	(*pos)++;
end:
	return ret;
}
