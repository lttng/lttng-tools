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

#include <common/dynamic-buffer.h>
#include <common/utils.h>
#include <assert.h>

/*
 * Round to (upper) power of two, val is returned if it already is a power of
 * two.
 */
static
size_t round_to_power_of_2(size_t val)
{
	int order;
	size_t rounded;

	order = utils_get_count_order_u64(val);
	assert(order >= 0);
	rounded = (1ULL << order);
	assert(rounded >= val);

	return rounded;
}

LTTNG_HIDDEN
void lttng_dynamic_buffer_init(struct lttng_dynamic_buffer *buffer)
{
	assert(buffer);
	memset(buffer, 0, sizeof(*buffer));
}

LTTNG_HIDDEN
int lttng_dynamic_buffer_append(struct lttng_dynamic_buffer *buffer,
		const void *buf, size_t len)
{
	int ret = 0;

	if (!buffer || (!buf && len)) {
		ret = -1;
		goto end;
	}

	if (len == 0) {
		/* Not an error, no-op. */
		goto end;
	}

	assert(buffer->_capacity >= buffer->size);
	if (buffer->_capacity < (len + buffer->size)) {
		ret = lttng_dynamic_buffer_set_capacity(buffer,
				buffer->_capacity +
				(len - (buffer->_capacity - buffer->size)));
		if (ret) {
			goto end;
		}
	}

	memcpy(buffer->data + buffer->size, buf, len);
	buffer->size += len;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_dynamic_buffer_append_buffer(struct lttng_dynamic_buffer *dst_buffer,
		struct lttng_dynamic_buffer *src_buffer)
{
	int ret;

	if (!dst_buffer || !src_buffer) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(dst_buffer, src_buffer->data,
			src_buffer->size);
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_dynamic_buffer_set_size(struct lttng_dynamic_buffer *buffer,
		size_t new_size)
{
	int ret = 0;

	if (!buffer) {
		goto end;
	}

	if (new_size == buffer->size) {
		goto end;
	}

	if (new_size > buffer->_capacity) {
		size_t original_size = buffer->size;
		size_t original_capacity = buffer->_capacity;

		ret = lttng_dynamic_buffer_set_capacity(buffer, new_size);
		if (ret) {
			goto end;
		}

		/*
		 * Zero-initialize the space that was left in the buffer at the
		 * before we increased its capacity (original capacity - original size).
		 * The newly acquired capacity (new capacity - original capacity)
		 * is zeroed by lttng_dynamic_buffer_set_capacity().
		 */
		memset(buffer->data + original_size, 0,
				original_capacity - original_size);
	} else if (new_size > buffer->size) {
		memset(buffer->data + buffer->size, 0, new_size - buffer->size);
	} else {
		/*
		 * Shrinking size. There is no need to zero-out the newly
		 * released memory as it will either be:
		 *   - overwritten by lttng_dynamic_buffer_append,
		 *   - expanded later, which will zero-out the memory
		 *
		 * Users of external APIs are encouraged to set the buffer's
		 * size _before_ making such calls.
		 */
	}
	buffer->size = new_size;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_dynamic_buffer_set_capacity(struct lttng_dynamic_buffer *buffer,
		size_t demanded_capacity)
{
	int ret = 0;
	void *new_buf;
	size_t new_capacity = round_to_power_of_2(demanded_capacity);

	if (!buffer || demanded_capacity < buffer->size) {
		/*
		 * Shrinking a buffer's size by changing its capacity is
		 * unsupported.
		 */
		ret = -1;
		goto end;
	}

	if (new_capacity == buffer->_capacity) {
		goto end;
	}

	/* Memory is initialized by the size increases. */
	new_buf = realloc(buffer->data, new_capacity);
	if (!new_buf) {
		ret = -1;
		goto end;
	}
	buffer->data = new_buf;
	buffer->_capacity = new_capacity;
end:
	return ret;
}

/* Release any memory used by the dynamic buffer. */
LTTNG_HIDDEN
void lttng_dynamic_buffer_reset(struct lttng_dynamic_buffer *buffer)
{
	if (!buffer) {
		return;
	}
	buffer->size = 0;
	buffer->_capacity = 0;
	free(buffer->data);
}
