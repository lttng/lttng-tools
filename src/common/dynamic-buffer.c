/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <common/utils.h>

/*
 * Round to (upper) power of two, val is returned if it already is a power of
 * two.
 */
static
size_t round_to_power_of_2(size_t val)
{
	size_t rounded;
	const int order = utils_get_count_order_u64(val);

	LTTNG_ASSERT(order >= 0);
	rounded = (1ULL << order);
	LTTNG_ASSERT(rounded >= val);

	return rounded;
}

void lttng_dynamic_buffer_init(struct lttng_dynamic_buffer *buffer)
{
	LTTNG_ASSERT(buffer);
	memset(buffer, 0, sizeof(*buffer));
}

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

	LTTNG_ASSERT(buffer->_capacity >= buffer->size);
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

int lttng_dynamic_buffer_append_buffer(struct lttng_dynamic_buffer *dst_buffer,
		const struct lttng_dynamic_buffer *src_buffer)
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

int lttng_dynamic_buffer_append_view(struct lttng_dynamic_buffer *buffer,
		const struct lttng_buffer_view *src)
{
	int ret;

	if (!buffer || !src) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_buffer_append(buffer, src->data,
			src->size);
end:
	return ret;
}

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
		ret = lttng_dynamic_buffer_set_capacity(buffer, new_size);
		if (ret) {
			goto end;
		}

		memset(buffer->data + buffer->size, 0, new_size - buffer->size);
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

int lttng_dynamic_buffer_set_capacity(struct lttng_dynamic_buffer *buffer,
		size_t demanded_capacity)
{
	int ret = 0;
	void *new_buf;
	size_t new_capacity = demanded_capacity ?
			round_to_power_of_2(demanded_capacity) : 0;

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
void lttng_dynamic_buffer_reset(struct lttng_dynamic_buffer *buffer)
{
	if (!buffer) {
		return;
	}

	buffer->size = 0;
	buffer->_capacity = 0;
	free(buffer->data);
	buffer->data = NULL;
}

size_t lttng_dynamic_buffer_get_capacity_left(
		struct lttng_dynamic_buffer *buffer)
{
	if (!buffer) {
		return 0;
	}

	return buffer->_capacity - buffer->size;
}
