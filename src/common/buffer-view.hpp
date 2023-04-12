/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_BUFFER_VIEW_H
#define LTTNG_BUFFER_VIEW_H

#include <common/macros.hpp>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lttng_dynamic_buffer;

struct lttng_buffer_view {
	const char *data;
	size_t size;
};

/**
 * Return a buffer view referencing a subset of the memory referenced by a raw
 * pointer.
 *
 * @src		Source buffer to reference
 * @offset	Offset to apply to the source memory buffer
 * @len		Length of the memory contents to reference.
 *
 * Note that a buffer view never assumes the ownership of the memory it
 * references.
 */
struct lttng_buffer_view lttng_buffer_view_init(const char *src, size_t offset, ptrdiff_t len);

/**
 * Checks if a buffer view is safe to access.
 *
 * After calling the buffer view creation functions, callers should verify
 * if the resquested length (if any is explicitly provided) could be mapped
 * to a new view.
 *
 * @view	Buffer view to validate
 */
bool lttng_buffer_view_is_valid(const struct lttng_buffer_view *view);

/**
 * Return a buffer view referencing a subset of the memory referenced by another
 * view.
 *
 * @src		Source view to reference
 * @offset	Offset to apply to the source memory content
 * @len		Length of the memory contents to reference. Passing -1 will
 *		cause the view to reference the whole view from the offset
 *		provided.
 *
 * Note that a buffer view never assumes the ownership of the memory it
 * references.
 */
struct lttng_buffer_view
lttng_buffer_view_from_view(const struct lttng_buffer_view *src, size_t offset, ptrdiff_t len);

/**
 * Return a buffer view referencing a subset of the memory referenced by a
 * dynamic buffer.
 *
 * @src		Source dynamic buffer to reference
 * @offset	Offset to apply to the source memory content
 * @len		Length of the memory contents to reference. Passing -1 will
 *		cause the view to reference the whole dynamic buffer from the
 *		offset provided.
 *
 * Note that a buffer view never assumes the ownership of the memory it
 * references.
 */
struct lttng_buffer_view lttng_buffer_view_from_dynamic_buffer(
	const struct lttng_dynamic_buffer *src, size_t offset, ptrdiff_t len);

/**
 * Verify that `buf` contains a string starting at `str` of length
 * `len_with_null_terminator`.
 *
 * @buf				The buffer view
 * @str				The start of the string
 * @len_with_null_terminator	Expected length of the string, including the
 * 				NULL terminator.
 */
bool lttng_buffer_view_contains_string(const struct lttng_buffer_view *buf,
				       const char *str,
				       size_t len_with_null_terminator);

#endif /* LTTNG_BUFFER_VIEW_H */
