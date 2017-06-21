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
#include <common/macros.h>

struct lttng_dynamic_buffer {
	char *data;
	/* size is the buffer's currently used capacity. */
	size_t size;
	/*
	 * capacity shall not be accessed by users directly, it is meant for
	 * internal use only.
	 */
	size_t _capacity;
};

/*
 * Initialize a dynamic buffer. This performs no allocation and is meant
 * to be used instead of memset or explicit initialization of the buffer.
 */
LTTNG_HIDDEN
void lttng_dynamic_buffer_init(struct lttng_dynamic_buffer *buffer);

/*
 * Append the content of a raw memory buffer to the end of a dynamic buffer
 * (after its current "size"). The dynamic buffer's size is increased by
 * "len", and its capacity is adjusted automatically.
 */
LTTNG_HIDDEN
int lttng_dynamic_buffer_append(struct lttng_dynamic_buffer *buffer,
		const void *buf, size_t len);

/*
 * Performs the same action as lttng_dynamic_buffer_append(), but using another
 * dynamic buffer as the source buffer. The source buffer's size is used in lieu
 * of "len".
 */
LTTNG_HIDDEN
int lttng_dynamic_buffer_append_buffer(struct lttng_dynamic_buffer *dst_buffer,
		struct lttng_dynamic_buffer *src_buffer);

/*
 * Set the buffer's size to new_size. The capacity of the buffer will
 * be expanded (if necessary) to accomodate new_size. Areas acquired by
 * a size increase will be zeroed.
 *
 * Be careful to expand the buffer's size _before_ calling out external
 * APIs (e.g. read(3)) which may populate the buffer as setting the size
 * after will zero-out the result of the operation.
 *
 * Shrinking a buffer does not zero the old content. If the buffer may contain
 * sensititve information, it must be cleared manually _before_ changing the
 * size.
 *
 * NOTE: It is striclty _invalid_ to access memory after _size_, regardless
 *       of prior calls to set_capacity().
 */
LTTNG_HIDDEN
int lttng_dynamic_buffer_set_size(struct lttng_dynamic_buffer *buffer,
		size_t new_size);

/*
 * Set the buffer's capacity to accomodate the new_capacity, allocating memory
 * as necessary. The buffer's content is preserved. Setting a buffer's capacity
 * is meant as a _hint_ to the underlying buffer and is only optimization; no
 * guarantee is offered that subsequent calls to append or set_size will succeed.
 *
 * If the current size > new_capacity, the operation will fail.
 */
LTTNG_HIDDEN
int lttng_dynamic_buffer_set_capacity(struct lttng_dynamic_buffer *buffer,
		size_t new_capacity);

/* Release any memory used by the dynamic buffer. */
LTTNG_HIDDEN
void lttng_dynamic_buffer_reset(struct lttng_dynamic_buffer *buffer);

#endif /* LTTNG_DYNAMIC_BUFFER_H */
