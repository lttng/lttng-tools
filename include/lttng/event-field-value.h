/*
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_FIELD_VALUE_H
#define LTTNG_EVENT_FIELD_VALUE_H

#include <stdint.h>

struct lttng_event_field_value;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types of a event field value expression.
 */
enum lttng_event_field_value_type {
	/*
	 * Unknown.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_UNKNOWN = -2,

	/*
	 * Returned by lttng_event_field_value_get_type() with an
	 * invalid parameter.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_INVALID = -1,

	/*
	 * Unsigned integer event field value.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT = 0,

	/*
	 * Signed integer event field value.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT = 1,

	/*
	 * Unsigned enumeration event field value.
	 *
	 * This type conceptually inherits
	 * `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT`.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM = 2,

	/*
	 * Signed enumeration event field value.
	 *
	 * This type conceptually inherits
	 * `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT`.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM = 3,

	/*
	 * Real event field value.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_REAL = 4,

	/*
	 * String event field value.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_STRING = 5,

	/*
	 * Array event field value.
	 */
	LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY = 6,
};

/*
 * Event field value API status codes.
 */
enum lttng_event_field_value_status {
	/*
	 * Event field value is not available.
	 */
	LTTNG_EVENT_FIELD_VALUE_STATUS_UNAVAILABLE = -2,

	/*
	 * Invalid parameter.
	 */
	LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID = -1,

	/*
	 * Success.
	 */
	LTTNG_EVENT_FIELD_VALUE_STATUS_OK = 0,
};

/*
 * Returns the type of the event field value `field_val`, or:
 *
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_UNKNOWN`:
 *     The type of `field_val` is unknown as of this version of the
 *     LTTng control library.
 *
 * `LTTNG_EVENT_FIELD_VALUE_TYPE_INVALID`:
 *     `field_val` is `NULL`.
 */
extern enum lttng_event_field_value_type lttng_event_field_value_get_type(
		const struct lttng_event_field_value *field_val);

/*
 * Sets `*val` to the raw value of the unsigned integer/enumeration
 * event field value `field_val`.
 *
 * Returns:
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID`:
 *     * `field_val` is `NULL`.
 *     * The type of `field_val` is not
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT` or
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM`.
 *     * `val` is `NULL`.
 */
extern enum lttng_event_field_value_status
lttng_event_field_value_unsigned_int_get_value(
		const struct lttng_event_field_value *field_val, uint64_t *val);

/*
 * Sets `*val` to the raw value of the signed integer/enumeration event
 * field value `field_val`.
 *
 * Returns:
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID`:
 *     * `field_val` is `NULL`.
 *     * The type of `field_val` is not
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT` or
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM`.
 *     * `val` is `NULL`.
 */
extern enum lttng_event_field_value_status
lttng_event_field_value_signed_int_get_value(
		const struct lttng_event_field_value *field_val, int64_t *val);

/*
 * Sets `*val` to the raw value of the real event field value
 * `field_val`.
 *
 * Returns:
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID`:
 *     * `field_val` is `NULL`.
 *     * The type of `field_val` is not
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_REAL`.
 *     * `val` is `NULL`.
 */
extern enum lttng_event_field_value_status
lttng_event_field_value_real_get_value(
		const struct lttng_event_field_value *field_val, double *val);

/*
 * Returns the raw value (an UTF-8 C string) of the string event field
 * value `field_val`, or `NULL` if:
 *
 * * `field_val` is `NULL`.
 * * The type of `field_val` is not
 *   `LTTNG_EVENT_FIELD_VALUE_TYPE_STRING`.
 */
extern const char *lttng_event_field_value_string_get_value(
		const struct lttng_event_field_value *field_val);

/*
 * Sets `*length` to the length (the number of contained elements) of
 * the array event field value `field_val`.
 *
 * Returns:
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID`:
 *     * `field_val` is `NULL`.
 *     * The type of `field_val` is not
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY`.
 *     * `length` is `NULL`.
 */
extern enum lttng_event_field_value_status
lttng_event_field_value_array_get_length(
		const struct lttng_event_field_value *field_val,
		unsigned int *length);

/*
 * Sets `*elem_field_val` to the event field value at index `index` in
 * the array event field value `field_val`.
 *
 * Returns:
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID`:
 *     * `field_val` is `NULL`.
 *     * The type of `field_val` is not
 *       `LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY`.
 *     * `index` is greater than or equal to the length of `field_val`,
 *       as returned by lttng_event_field_value_array_get_length().
 *
 * `LTTNG_EVENT_FIELD_VALUE_STATUS_UNAVAILABLE`:
 *     * No event field value exists at index `index` within
 *       `field_val`.
 */
extern enum lttng_event_field_value_status
lttng_event_field_value_array_get_element_at_index(
		const struct lttng_event_field_value *field_val,
		unsigned int index,
		const struct lttng_event_field_value **elem_field_val);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_FIELD_VALUE_H */
