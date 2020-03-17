/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRACKER_INTERNAL_H
#define LTTNG_TRACKER_INTERNAL_H

#include <common/macros.h>
#include <common/dynamic-buffer.h>
#include <lttng/constant.h>
#include <lttng/tracker.h>
#include <stdbool.h>

struct lttng_tracker_id {
	enum lttng_tracker_id_type type;
	int value;
	char *string;
};

struct lttng_tracker_ids {
	struct lttng_tracker_id *id_array;
	unsigned int count;
};

LTTNG_HIDDEN
bool lttng_tracker_id_is_equal(const struct lttng_tracker_id *left,
		const struct lttng_tracker_id *right);

/*
 * A copy acts like memcpy. It does not allocate new memory.
 */
LTTNG_HIDDEN
int lttng_tracker_id_copy(struct lttng_tracker_id *dest,
		const struct lttng_tracker_id *src);

/*
 * Duplicate an lttng_tracker_id.
 * The returned object must be freed via lttng_tracker_id_destroy.
 */
LTTNG_HIDDEN
struct lttng_tracker_id *lttng_tracker_id_duplicate(
		const struct lttng_tracker_id *src);

/*
 * Allocate a new list of lttng_tracker_id.
 * The returned object must be freed via lttng_tracker_ids_destroy.
 */
LTTNG_HIDDEN
struct lttng_tracker_ids *lttng_tracker_ids_create(unsigned int base_count);

/*
 * Return the non-const pointer of an element at index "index" of a
 * lttng_tracker_ids.
 *
 * The ownership of the lttng_tracker_id element is NOT transfered.
 * The returned object can NOT be freed via lttng_tracker_id_destroy.
 */
LTTNG_HIDDEN
struct lttng_tracker_id *lttng_tracker_ids_get_pointer_of_index(
		const struct lttng_tracker_ids *list, unsigned int index);

/*
 * Serialize a ids collection to a lttng_dynamic_buffer.
 * Return LTTNG_OK on success, negative lttng error code on error.
 */
LTTNG_HIDDEN
int lttng_tracker_ids_serialize(const struct lttng_tracker_ids *ids,
		struct lttng_dynamic_buffer *buffer);

#endif /* LTTNG_TRACKER_INTERNAL_H */
