/*
 * SPDX-FileCopyrightText: 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_FIELD_VALUE_H
#define LTTNG_EVENT_FIELD_VALUE_H

#include <lttng/lttng-export.h>

#include <stdint.h>

struct lttng_event_field_value;

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_ev_field_val
@{
*/

/*!
@brief
    Event field value type.

Get the type of an event field value with
lttng_event_field_value_get_type().
*/
enum lttng_event_field_value_type {
	/// Unsigned integer.
	LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT = 0,

	/// Signed integer.
	LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT = 1,

	/*!
	Unsigned enumeration.

	Conceptually inherits
	#LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT.
	*/
	LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM = 2,

	/*!
	Signed enumeration.

	Conceptually inherits
	#LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT.
	*/
	LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM = 3,

	/// Real number.
	LTTNG_EVENT_FIELD_VALUE_TYPE_REAL = 4,

	/// String.
	LTTNG_EVENT_FIELD_VALUE_TYPE_STRING = 5,

	/// Array.
	LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY = 6,

	/// Unsatisfied precondition.
	LTTNG_EVENT_FIELD_VALUE_TYPE_INVALID = -1,

	/// Unknown (error).
	LTTNG_EVENT_FIELD_VALUE_TYPE_UNKNOWN = -2,
};

/*!
@brief
    Return type of event field value API functions.
*/
enum lttng_event_field_value_status {
	/// Success.
	LTTNG_EVENT_FIELD_VALUE_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID = -1,

	/// Event field value is not available.
	LTTNG_EVENT_FIELD_VALUE_STATUS_UNAVAILABLE = -2,
};

/*!
@brief
    Returns the type of the event field value \lt_p{field_val}.

@param[in] field_val
    Event field value of which to get the type.

@returns
    Type of \lt_p{field_val}.

@pre
    @lt_pre_not_null{field_val}
*/
LTTNG_EXPORT extern enum lttng_event_field_value_type
lttng_event_field_value_get_type(const struct lttng_event_field_value *field_val);

/*!
@brief
    Sets \lt_p{*val} to the raw value of the
    unsigned integer event field value \lt_p{field_val}.

@param[in] field_val
    Unsigned integer event field value of which to get the raw value.
@param[out] val
    <strong>On success</strong>, this function sets \lt_p{*val}
    to the raw value of \lt_p{field_val}.

@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{field_val}
    - \lt_p{field_val} has the type
      #LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_INT or
      #LTTNG_EVENT_FIELD_VALUE_TYPE_UNSIGNED_ENUM.
    @lt_pre_not_null{val}

@sa lttng_event_field_value_signed_int_get_value() --
    Get the raw value of a signed integer event field value.
*/
LTTNG_EXPORT extern enum lttng_event_field_value_status
lttng_event_field_value_unsigned_int_get_value(const struct lttng_event_field_value *field_val,
					       uint64_t *val);

/*!
@brief
    Sets \lt_p{*val} to the raw value of the
    signed integer event field value \lt_p{field_val}.

@param[in] field_val
    Signed integer event field value of which to get the raw value.
@param[out] val
    <strong>On success</strong>, this function sets \lt_p{*val}
    to the raw value of \lt_p{field_val}.

@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{field_val}
    - \lt_p{field_val} has the type
      #LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_INT or
      #LTTNG_EVENT_FIELD_VALUE_TYPE_SIGNED_ENUM.
    @lt_pre_not_null{val}

@sa lttng_event_field_value_unsigned_int_get_value() --
    Get the raw value of an unsigned integer event field value.
*/
LTTNG_EXPORT extern enum lttng_event_field_value_status
lttng_event_field_value_signed_int_get_value(const struct lttng_event_field_value *field_val,
					     int64_t *val);

/*!
@brief
    Sets \lt_p{*val} to the raw value of the
    real number event field value \lt_p{field_val}.

@param[in] field_val
    Real number event field value of which to get the raw value.
@param[out] val
    <strong>On success</strong>, this function sets \lt_p{*val}
    to the raw value of \lt_p{field_val}.

@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{field_val}
    @lt_pre_has_type{field_val,LTTNG_EVENT_FIELD_VALUE_TYPE_REAL}
    @lt_pre_not_null{val}
*/
LTTNG_EXPORT extern enum lttng_event_field_value_status
lttng_event_field_value_real_get_value(const struct lttng_event_field_value *field_val,
				       double *val);

/*!
@brief
    Sets \lt_p{*val} to the raw value of the
    string event field value \lt_p{field_val}.

@param[in] field_val
    String event field value of which to get the raw value.
@param[out] val
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*val}
    to the raw value of \lt_p{field_val}.

    \lt_p{field_val} owns \lt_p{*val}.

    \lt_p{*val} remains valid until the next function call
    with \lt_p{field_val}.
    @endparblock

@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{field_val}
    @lt_pre_has_type{field_val,LTTNG_EVENT_FIELD_VALUE_TYPE_STRING}
    @lt_pre_not_null{val}
*/
LTTNG_EXPORT extern enum lttng_event_field_value_status
lttng_event_field_value_string_get_value(const struct lttng_event_field_value *field_val,
					 const char **val);

/*!
@brief
    Sets \lt_p{*length} to the length of the
    array event field value \lt_p{field_val}.

@param[in] field_val
    Array event field value of which to get the length.
@param[out] length
    <strong>On success</strong>, this function sets \lt_p{*length}
    to the length of \lt_p{field_val}.

@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{field_val}
    @lt_pre_has_type{field_val,LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY}
    @lt_pre_not_null{length}

@sa lttng_event_field_value_array_get_element_at_index() --
    Get an element of a an array event field value by index.
*/
LTTNG_EXPORT extern enum lttng_event_field_value_status
lttng_event_field_value_array_get_length(const struct lttng_event_field_value *field_val,
					 unsigned int *length);

/*!
@brief
    Sets \lt_p{*elem_field_val} to the element of the
    array event field value \lt_p{field_val} at the index
    \lt_p{index}.

It's possible that \lt_p{field_val} doesn't actually have any element at
the index \lt_p{index}, in which case this function returns
#LTTNG_EVENT_FIELD_VALUE_STATUS_UNAVAILABLE.

@param[in] field_val
    Array event field value of which to get the element at the index
    \lt_p{index}.
@param[in] index
    Index of the element to get from \lt_p{field_val}.
@param[out] elem_field_val
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*elem_field_val} to the element of \lt_p{field_val} at the
    index \lt_p{index}.

    \lt_p{field_val} owns \lt_p{*elem_field_val}.

    \lt_p{*elem_field_val} remains valid until the next function call
    with \lt_p{field_val}.
    @endparblock

@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_OK
    Success.
@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_EVENT_FIELD_VALUE_STATUS_UNAVAILABLE
    The element of \lt_p{field_val} at the
    index \lt_p{index} is not available.

@pre
    @lt_pre_not_null{field_val}
    @lt_pre_has_type{field_val,LTTNG_EVENT_FIELD_VALUE_TYPE_ARRAY}
    - \lt_p{index} is less than the number of elements
      of \lt_p{field_val} (as given by
      lttng_event_field_value_array_get_length()).
    @lt_pre_not_null{elem_field_val}

@sa lttng_event_field_value_array_get_length() --
    Get the length of an array event field value.
*/
LTTNG_EXPORT extern enum lttng_event_field_value_status
lttng_event_field_value_array_get_element_at_index(
	const struct lttng_event_field_value *field_val,
	unsigned int index,
	const struct lttng_event_field_value **elem_field_val);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_FIELD_VALUE_H */
