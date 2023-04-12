/*
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_FIELD_VALUE_INTERNAL_H
#define LTTNG_EVENT_FIELD_VALUE_INTERNAL_H

#include <common/dynamic-array.hpp>

#include <lttng/event-field-value.h>

#include <stdint.h>

struct lttng_event_field_value {
	enum lttng_event_field_value_type type;
};

/*
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT`.
 */
struct lttng_event_field_value_uint {
	struct lttng_event_field_value parent;
	uint64_t val;
};

/*
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT`.
 */
struct lttng_event_field_value_int {
	struct lttng_event_field_value parent;
	int64_t val;
};

/*
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM` and
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM` (base).
 */
struct lttng_event_field_value_enum {
	struct lttng_event_field_value parent;

	/*
	 * Array of `char *` (owned by this).
	 */
	struct lttng_dynamic_pointer_array labels;
};

/*
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM`.
 */
struct lttng_event_field_value_enum_uint {
	struct lttng_event_field_value_enum parent;
	uint64_t val;
};

/*
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM`.
 */
struct lttng_event_field_value_enum_int {
	struct lttng_event_field_value_enum parent;
	int64_t val;
};

/* `LTTNG_EVENT_FIELD_VALUE_TYPE_REAL` */
struct lttng_event_field_value_real {
	struct lttng_event_field_value parent;
	double val;
};

/* `LTTNG_EVENT_FIELD_VALUE_TYPE_STRING` */
struct lttng_event_field_value_string {
	struct lttng_event_field_value parent;

	/* Owned by this */
	char *val;
};

/* `LTTNG_EVENT_FIELD_VALUE_TYPE_STRING` */
struct lttng_event_field_value_array {
	struct lttng_event_field_value parent;

	/*
	 * Array of `struct lttng_event_field_value *` (owned by this).
	 *
	 * A `NULL` element means it's unavailable
	 * (`LTTNG_EVENT_FIELD_VALUE_STATUS_UNAVAILABLE` status).
	 */
	struct lttng_dynamic_pointer_array elems;
};

/*
 * This is internal since the session daemon knows nothing about the
 * enumeration fields produced by the kernel tracer. Indeed, the kernel tracer
 * manages its own metadata which remains opaque to the rest of the toolchain.
 *
 * Enumerations could be supported for the user space tracer, but it is not the
 * case right now.
 */

/*
 * Sets `*count` to the number of labels of the enumeration event field
 * value `field_val`.
 *
 * Returns:
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID`:
 *     * `field_val` is `NULL`.
 *     * The type of `field_val` is not
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM` or
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM`.
 *     * `count` is `NULL`.
 */
enum lttng_event_field_value_status
lttng_event_field_value_enum_get_label_count(const struct lttng_event_field_value *field_val,
					     unsigned int *count);

/*
 * Returns the label at index `index` of the enumeration event field
 * value `field_val`, or `NULL` if:
 *
 * * `field_val` is `NULL`.
 * * The type of `field_val` is not
 *   `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM` or
 *   `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM`.
 * * `index` is greater than or equal to the label count of `field_val`,
 *   as returned by lttng_event_field_value_enum_get_label_count().
 */
const char *
lttng_event_field_value_enum_get_label_at_index(const struct lttng_event_field_value *field_val,
						unsigned int index);

struct lttng_event_field_value *lttng_event_field_value_uint_create(uint64_t val);

struct lttng_event_field_value *lttng_event_field_value_int_create(int64_t val);

struct lttng_event_field_value *lttng_event_field_value_enum_uint_create(uint64_t val);

struct lttng_event_field_value *lttng_event_field_value_enum_int_create(int64_t val);

struct lttng_event_field_value *lttng_event_field_value_real_create(double val);

struct lttng_event_field_value *lttng_event_field_value_string_create(const char *val);

struct lttng_event_field_value *lttng_event_field_value_string_create_with_size(const char *val,
										size_t size);

struct lttng_event_field_value *lttng_event_field_value_array_create();

int lttng_event_field_value_enum_append_label(struct lttng_event_field_value *field_val,
					      const char *label);

int lttng_event_field_value_enum_append_label_with_size(struct lttng_event_field_value *field_val,
							const char *label,
							size_t size);

int lttng_event_field_value_array_append(struct lttng_event_field_value *array_field_val,
					 struct lttng_event_field_value *field_val);

int lttng_event_field_value_array_append_unavailable(
	struct lttng_event_field_value *array_field_val);

void lttng_event_field_value_destroy(struct lttng_event_field_value *field_val);

#endif /* LTTNG_EVENT_FIELD_VALUE_INTERNAL_H */
