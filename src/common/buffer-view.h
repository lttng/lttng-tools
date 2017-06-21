/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_BUFFER_VIEW_H
#define LTTNG_BUFFER_VIEW_H

#include <stddef.h>
#include <stdint.h>
#include <common/macros.h>

struct lttng_dynamic_buffer;

struct lttng_buffer_view {
	const char *data;
	size_t size;
};

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
LTTNG_HIDDEN
struct lttng_buffer_view lttng_buffer_view_from_view(
		const struct lttng_buffer_view *src, size_t offset,
		ptrdiff_t len);

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
LTTNG_HIDDEN
struct lttng_buffer_view lttng_buffer_view_from_dynamic_buffer(
		const struct lttng_dynamic_buffer *src, size_t offset,
		ptrdiff_t len);

#endif /* LTTNG_BUFFER_VIEW_H */
