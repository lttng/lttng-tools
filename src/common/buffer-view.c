/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/buffer-view.h>
#include <common/dynamic-buffer.h>
#include <common/error.h>

struct lttng_buffer_view lttng_buffer_view_init(
		const char *src, size_t offset, ptrdiff_t len)
{
	struct lttng_buffer_view view = { .data = src + offset, .size = len };
	return view;
}

bool lttng_buffer_view_is_valid(const struct lttng_buffer_view *view)
{
	return view && view->data && view->size > 0;
}

struct lttng_buffer_view lttng_buffer_view_from_view(
		const struct lttng_buffer_view *src, size_t offset,
		ptrdiff_t len)
{
	struct lttng_buffer_view view = { .data = NULL, .size = 0 };

	LTTNG_ASSERT(src);

	if (offset > src->size) {
		ERR("Attempt to create buffer view from another view with invalid offset (offset > source size): source size = %zu, offset in source = %zu, length = %zd",
				src->size, offset, len);
		goto end;
	}

	if (len != -1 && len > (src->size - offset)) {
		ERR("Attempt to create buffer view from another view with invalid length (length > space left after offset in source): source size = %zu, offset in source = %zu, length = %zd",
				src->size, offset, len);
		goto end;
	}

	view.data = src->data + offset;
	view.size = len == -1 ? (src->size - offset) : len;
end:
	return view;
}

struct lttng_buffer_view lttng_buffer_view_from_dynamic_buffer(
		const struct lttng_dynamic_buffer *src, size_t offset,
		ptrdiff_t len)
{
	struct lttng_buffer_view view = { .data = NULL, .size = 0 };

	LTTNG_ASSERT(src);

	if (offset > src->size) {
		ERR("Attempt to create buffer view from a dynamic buffer with invalid offset (offset > source size): source size = %zu, offset in source = %zu, length = %zd",
				src->size, offset, len);
		goto end;
	}

	if (len != -1 && len > (src->size - offset)) {
		ERR("Attempt to create buffer view from a dynamic buffer with invalid length (length > space left after offset in source): source size = %zu, offset in source = %zu, length = %zd",
				src->size, offset, len);
		goto end;
	}

	view.data = src->data + offset;
	view.size = len == -1 ? (src->size - offset) : len;
end:
	return view;
}

bool lttng_buffer_view_contains_string(const struct lttng_buffer_view *buf,
		const char *str,
		size_t len_with_null_terminator)
{
	const char *past_buf_end;
	size_t max_str_len_with_null_terminator;
	size_t str_len;
	bool ret;

	past_buf_end = buf->data + buf->size;

	/* Is the start of the string in the buffer view? */
	if (str < buf->data || str >= past_buf_end) {
		ret = false;
		goto end;
	}

	/*
	 * Max length the string could have to fit in the buffer, including
	 * NULL terminator.
	 */
	max_str_len_with_null_terminator = past_buf_end - str;

	/* Could the string even fit in the buffer? */
	if (len_with_null_terminator > max_str_len_with_null_terminator) {
		ret = false;
		goto end;
	}

	str_len = lttng_strnlen(str, max_str_len_with_null_terminator);
	if (str_len != (len_with_null_terminator - 1)) {
		ret = false;
		goto end;
	}

	ret = true;

end:
	return ret;
}
