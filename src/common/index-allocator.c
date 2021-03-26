/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <assert.h>
#include <inttypes.h>

#include <urcu.h>
#include <urcu/list.h>

#include "macros.h"
#include "error.h"

#include "index-allocator.h"

struct lttng_index_allocator {
	struct cds_list_head unused_list;
	uint64_t size;
	uint64_t position;
	uint64_t nb_allocated_indexes;
};

struct lttng_index {
	uint64_t index;
	struct cds_list_head head;
};

struct lttng_index_allocator *lttng_index_allocator_create(
		uint64_t index_count)
{
	struct lttng_index_allocator *allocator = NULL;

	allocator = zmalloc(sizeof(*allocator));
	if (!allocator) {
		PERROR("Failed to allocate index allocator");
		goto end;
	}

	allocator->size = index_count;
	allocator->position = 0;
	allocator->nb_allocated_indexes = 0;

	CDS_INIT_LIST_HEAD(&allocator->unused_list);

end:
	return allocator;
}

uint64_t lttng_index_allocator_get_index_count(struct lttng_index_allocator *allocator)
{
	return allocator->nb_allocated_indexes;
}

enum lttng_index_allocator_status lttng_index_allocator_alloc(
		struct lttng_index_allocator *allocator,
		uint64_t *allocated_index)
{
	enum lttng_index_allocator_status status =
			LTTNG_INDEX_ALLOCATOR_STATUS_OK;

	if (cds_list_empty(&allocator->unused_list)) {
		if (allocator->position >= allocator->size) {
			/* No indices left. */
			status = LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY;
			goto end;
		}

		*allocated_index = allocator->position++;
	} else {
		struct lttng_index *index;

		index = cds_list_first_entry(&allocator->unused_list,
				typeof(*index), head);
		cds_list_del(&index->head);
		*allocated_index = index->index;
		free(index);
	}

	allocator->nb_allocated_indexes++;
end:
	return status;
}

enum lttng_index_allocator_status lttng_index_allocator_release(
		struct lttng_index_allocator *allocator, uint64_t idx)
{
	struct lttng_index *index = NULL;
	enum lttng_index_allocator_status status =
			LTTNG_INDEX_ALLOCATOR_STATUS_OK;

	assert(idx < allocator->size);

	index = zmalloc(sizeof(*index));
	if (!index) {
		PERROR("Failed to allocate free index queue");
		status = LTTNG_INDEX_ALLOCATOR_STATUS_ERROR;
		goto end;
	}

	index->index = idx;
	cds_list_add_tail(&index->head, &allocator->unused_list);
	allocator->nb_allocated_indexes--;

end:
	return status;
}

void lttng_index_allocator_destroy(struct lttng_index_allocator *allocator)
{
	struct lttng_index *index = NULL, *tmp_index = NULL;

	if (!allocator) {
		return;
	}

	if (lttng_index_allocator_get_index_count(allocator) > 0) {
		WARN("Destroying index allocator with %" PRIu64
				" slot indexes still in use",
				lttng_index_allocator_get_index_count(allocator));
	}

	cds_list_for_each_entry_safe(index, tmp_index,
			&allocator->unused_list, head) {
		cds_list_del(&index->head);
		free(index);
	}

	free(allocator);
}
