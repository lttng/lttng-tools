/*
 * Copyright 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "bytecode.h"

#include <errno.h>

#include "common/align.h"

#define INIT_ALLOC_SIZE 4

static inline int get_count_order(unsigned int count)
{
	int order;

	order = lttng_fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

LTTNG_HIDDEN
int bytecode_init(struct lttng_filter_bytecode_alloc **fb)
{
	uint32_t alloc_len;

	alloc_len = sizeof(struct lttng_filter_bytecode_alloc) + INIT_ALLOC_SIZE;
	*fb = calloc(alloc_len, 1);
	if (!*fb) {
		return -ENOMEM;
	} else {
		(*fb)->alloc_len = alloc_len;
		return 0;
	}
}

LTTNG_HIDDEN
int32_t bytecode_reserve(struct lttng_filter_bytecode_alloc **fb, uint32_t align, uint32_t len)
{
	int32_t ret;
	uint32_t padding = offset_align((*fb)->b.len, align);
	uint32_t new_len = (*fb)->b.len + padding + len;
	uint32_t new_alloc_len = sizeof(struct lttng_filter_bytecode_alloc) + new_len;
	uint32_t old_alloc_len = (*fb)->alloc_len;

	if (new_len > LTTNG_FILTER_MAX_LEN)
		return -EINVAL;

	if (new_alloc_len > old_alloc_len) {
		struct lttng_filter_bytecode_alloc *newptr;

		new_alloc_len =
			max_t(uint32_t, 1U << get_count_order(new_alloc_len), old_alloc_len << 1);
		newptr = realloc(*fb, new_alloc_len);
		if (!newptr)
			return -ENOMEM;
		*fb = newptr;
		/* We zero directly the memory from start of allocation. */
		memset(&((char *) *fb)[old_alloc_len], 0, new_alloc_len - old_alloc_len);
		(*fb)->alloc_len = new_alloc_len;
	}
	(*fb)->b.len += padding;
	ret = (*fb)->b.len;
	(*fb)->b.len += len;
	return ret;
}

LTTNG_HIDDEN
int bytecode_push(struct lttng_filter_bytecode_alloc **fb, const void *data,
		uint32_t align, uint32_t len)
{
	int32_t offset;

	offset = bytecode_reserve(fb, align, len);
	if (offset < 0)
		return offset;
	memcpy(&(*fb)->b.data[offset], data, len);
	return 0;
}

LTTNG_HIDDEN
int bytecode_push_logical(struct lttng_filter_bytecode_alloc **fb,
		struct logical_op *data,
		uint32_t align, uint32_t len,
		uint16_t *skip_offset)
{
	int32_t offset;

	offset = bytecode_reserve(fb, align, len);
	if (offset < 0)
		return offset;
	memcpy(&(*fb)->b.data[offset], data, len);
	*skip_offset =
		(void *) &((struct logical_op *) &(*fb)->b.data[offset])->skip_offset
			- (void *) &(*fb)->b.data[0];
	return 0;
}

/*
 * Allocate an lttng_bytecode object and copy the given original bytecode.
 *
 * Return allocated bytecode or NULL on error.
 */
LTTNG_HIDDEN
struct lttng_filter_bytecode *lttng_filter_bytecode_copy(
		const struct lttng_filter_bytecode *orig_f)
{
	struct lttng_filter_bytecode *bytecode = NULL;

	bytecode = zmalloc(sizeof(*bytecode) + orig_f->len);
	if (!bytecode) {
		goto error;
	}

	memcpy(bytecode, orig_f, sizeof(*bytecode) + orig_f->len);

error:
	return bytecode;
}
