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

#ifndef LTTNG_DYNAMIC_BUFFER_H
#define LTTNG_DYNAMIC_BUFFER_H

#include <stddef.h>
#include <stdint.h>

struct lttng_dynamic_buffer {
	char *data;
	size_t size;
	size_t capacity;
};

void lttng_dynamic_buffer_init(struct lttng_dynamic_buffer *buffer);

int lttng_dynamic_buffer_append(struct lttng_dynamic_buffer *buffer,
		const void *buf, size_t len);

int lttng_dynamic_buffer_append_buffer(struct lttng_dynamic_buffer *dst_buffer,
		struct lttng_dynamic_buffer *src_buffer);

/*
 * Set the buffer's size to new_size. The capacity of the buffer will
 * be expanded (if necessary) to accomodate new_size. Areas acquired by
 * an enlarging new_size _will be zeroed_.
 *
 * Be careful to expand the buffer's size _before_ calling out external
 * APIs (e.g. read(3)) which may populate the buffer as setting the size
 * _after_ will zero-out the result of the operation.
 */
int lttng_dynamic_buffer_set_size(struct lttng_dynamic_buffer *buffer,
		size_t new_size);

/*
 * Set the buffer's capacity to accomodate the new_capacity, allocating memory
 * as necessary. The buffer's content is preserved.
 *
 * If the current size > new_capacity, the operation will fail.
 */
int lttng_dynamic_buffer_set_capacity(struct lttng_dynamic_buffer *buffer,
		size_t new_capacity);

/* Release any memory used by the dynamic buffer. */
void lttng_dynamic_buffer_reset(struct lttng_dynamic_buffer *buffer);

#endif /* LTTNG_DYNAMIC_BUFFER_H */
