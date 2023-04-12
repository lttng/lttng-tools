/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _COMMON_INDEX_ALLOCATOR_H
#define _COMMON_INDEX_ALLOCATOR_H

#include <lttng/lttng-export.h>

#include <inttypes.h>

struct lttng_index_allocator;

enum lttng_index_allocator_status {
	LTTNG_INDEX_ALLOCATOR_STATUS_OK,
	LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY,
	LTTNG_INDEX_ALLOCATOR_STATUS_ERROR,
};

/*
 * Create an index allocator of `index_count` slots.
 */
extern "C" LTTNG_EXPORT struct lttng_index_allocator *
lttng_index_allocator_create(uint64_t index_count);

/*
 * Get the number of indexes currently in use.
 */
extern "C" LTTNG_EXPORT uint64_t
lttng_index_allocator_get_index_count(struct lttng_index_allocator *allocator);

/*
 * Allocate (i.e. reserve) a slot.
 */
extern "C" LTTNG_EXPORT enum lttng_index_allocator_status
lttng_index_allocator_alloc(struct lttng_index_allocator *allocator, uint64_t *index);

/*
 * Release a slot by index. The slot will be re-used by the index allocator
 * in future 'alloc' calls.
 */
extern "C" LTTNG_EXPORT enum lttng_index_allocator_status
lttng_index_allocator_release(struct lttng_index_allocator *allocator, uint64_t index);

/*
 * Destroy an index allocator.
 */
extern "C" LTTNG_EXPORT void lttng_index_allocator_destroy(struct lttng_index_allocator *allocator);

#endif /* _COMMON_INDEX_ALLOCATOR_H */
