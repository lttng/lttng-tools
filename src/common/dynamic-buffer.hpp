/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_DYNAMIC_BUFFER_H
#define LTTNG_DYNAMIC_BUFFER_H

#include <common/macros.hpp>

#include <stddef.h>
#include <stdint.h>

struct lttng_buffer_view;

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
void lttng_dynamic_buffer_init(struct lttng_dynamic_buffer *buffer);

/*
 * Append the content of a raw memory buffer to the end of a dynamic buffer
 * (after its current "size"). The dynamic buffer's size is increased by
 * "len", and its capacity is adjusted automatically.
 */
int lttng_dynamic_buffer_append(struct lttng_dynamic_buffer *buffer, const void *buf, size_t len);

/*
 * Performs the same action as lttng_dynamic_buffer_append(), but using another
 * dynamic buffer as the source buffer. The source buffer's size is used in lieu
 * of "len".
 */
int lttng_dynamic_buffer_append_buffer(struct lttng_dynamic_buffer *dst_buffer,
				       const struct lttng_dynamic_buffer *src_buffer);

/*
 * Performs the same action as lttng_dynamic_buffer_append(), but using a
 * buffer view as the source buffer. The source buffer's size is used in lieu
 * of "len".
 */
int lttng_dynamic_buffer_append_view(struct lttng_dynamic_buffer *buffer,
				     const struct lttng_buffer_view *view);

/*
 * Set the buffer's size to new_size. The capacity of the buffer will
 * be expanded (if necessary) to accommodates new_size. Areas acquired by
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
int lttng_dynamic_buffer_set_size(struct lttng_dynamic_buffer *buffer, size_t new_size);

/*
 * Set the buffer's capacity to accommodates the new_capacity, allocating memory
 * as necessary. The buffer's content is preserved. Setting a buffer's capacity
 * is meant as a _hint_ to the underlying buffer and is only optimization; no
 * guarantee is offered that subsequent calls to append or set_size will succeed.
 *
 * If the current size > new_capacity, the operation will fail.
 */
int lttng_dynamic_buffer_set_capacity(struct lttng_dynamic_buffer *buffer, size_t new_capacity);

/* Release any memory used by the dynamic buffer. */
void lttng_dynamic_buffer_reset(struct lttng_dynamic_buffer *buffer);

/* Get the space left in the buffer before a new resize is needed. */
size_t lttng_dynamic_buffer_get_capacity_left(struct lttng_dynamic_buffer *buffer);

#endif /* LTTNG_DYNAMIC_BUFFER_H */
