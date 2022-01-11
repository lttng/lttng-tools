/*
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stddef.h>
#include <common/index-allocator.h>

/*
 * These are symbols that were erroneously exposed and have since been removed.
 */

size_t default_channel_subbuf_size;
size_t default_kernel_channel_subbuf_size;
size_t default_metadata_subbuf_size;
size_t default_ust_pid_channel_subbuf_size;
size_t default_ust_uid_channel_subbuf_size;

const char * const config_element_pid_tracker;
const char * const config_element_target_pid;
const char * const config_element_targets;
const char * const config_element_trackers;

enum lttng_index_allocator_status lttng_index_allocator_alloc(
		struct lttng_index_allocator *a, uint64_t *b)
{
	return LTTNG_INDEX_ALLOCATOR_STATUS_ERROR;
}

struct lttng_index_allocator* lttng_index_allocator_create(uint64_t a)
{
	return NULL;
}

void lttng_index_allocator_destroy(struct lttng_index_allocator *a)
{
}

uint64_t lttng_index_allocator_get_index_count(
		struct lttng_index_allocator *a)
{
	return -1ULL;
}

enum lttng_index_allocator_status lttng_index_allocator_release(
		struct lttng_index_allocator *a, uint64_t b)
{
	return LTTNG_INDEX_ALLOCATOR_STATUS_ERROR;
}
