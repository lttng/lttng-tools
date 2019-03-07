/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/buffer-view.h>
#include <common/dynamic-buffer.h>
#include <common/error.h>
#include <assert.h>

LTTNG_HIDDEN
struct lttng_buffer_view lttng_buffer_view_init(
		const char *src, size_t offset, ptrdiff_t len)
{
	struct lttng_buffer_view view = { .data = src + offset, .size = len };
	return view;
}

LTTNG_HIDDEN
struct lttng_buffer_view lttng_buffer_view_from_view(
		const struct lttng_buffer_view *src, size_t offset,
		ptrdiff_t len)
{
	struct lttng_buffer_view view = { .data = NULL, .size = 0 };

	assert(src);

	if (offset > src->size) {
		ERR("Attempt to create buffer view with invalid offset");
		goto end;
	}

	if (len != -1 && len > (src->size - offset)) {
		ERR("Attempt to create buffer view with invalid length");
		goto end;
	}

	view.data = src->data + offset;
	view.size = len == -1 ? (src->size - offset) : len;
end:
	return view;
}

LTTNG_HIDDEN
struct lttng_buffer_view lttng_buffer_view_from_dynamic_buffer(
		const struct lttng_dynamic_buffer *src, size_t offset,
		ptrdiff_t len)
{
	struct lttng_buffer_view view = { .data = NULL, .size = 0 };

	assert(src);

	if (offset > src->size) {
		ERR("Attempt to create buffer view with invalid offset");
		goto end;
	}

	if (len != -1 && len > (src->size - offset)) {
		ERR("Attempt to create buffer view with invalid length");
		goto end;
	}

	view.data = src->data + offset;
	view.size = len == -1 ? (src->size - offset) : len;
end:
	return view;
}
