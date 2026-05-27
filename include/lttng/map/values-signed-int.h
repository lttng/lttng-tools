/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_VALUES_SIGNED_INT_H
#define LTTNG_MAP_VALUES_SIGNED_INT_H

#include <lttng/lttng-export.h>
#include <lttng/map/values.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_value
@{
*/

/*!
@brief
    Sets \lt_p{*value} to the value of the entry at \lt_p{index} in the
    signed integer \lt_obj_map_values \lt_p{values}.

The entry index space is defined by the parent map channel, regardless
of the channel's key type: use the channel API to translate a key
(for example a string) to its corresponding index.

@param[in] values
    Signed integer map values object of which to get an entry value.
@param[in] index
    Index of the entry of which to get the value from \lt_p{values}.
@param[out] value
    <strong>On success</strong>, this function sets \lt_p{*value} to
    the value of the entry at \lt_p{index} in \lt_p{values}.

@retval #LTTNG_MAP_VALUES_STATUS_OK
    Success.
@retval #LTTNG_MAP_VALUES_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{values}
    - lttng_map_channel_get_value_type() returns
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32,
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64, or
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX
      with the map channel from which \lt_p{values} was obtained.
    - \lt_p{index} is the index of a valid key of the map channel from
      which \lt_p{values} was obtained
      (see lttng_map_channel_get_keys()).
    @lt_pre_not_null{value}

@sa lttng_map_values_signed_int_has_overflow_at_index() --
    Returns whether an entry of a signed integer map values object has
    overflowed.
*/
LTTNG_EXPORT extern enum lttng_map_values_status lttng_map_values_signed_int_get_value_at_index(
	const struct lttng_map_values *values, uint64_t index, int64_t *value);

/*!
@brief
    Sets \lt_p{*has_overflow} to whether or not the entry at
    \lt_p{index} in the signed integer \lt_obj_map_values \lt_p{values}
    has had at least one arithmetic update wrap around (modular
    arithmetic) because the result could not be represented in the
    \ref api-map-group-prop-effective-value-type "effective value type"
    of the map group.

@param[in] values
    Signed integer map values object of which to get an entry overflow
    indicator.
@param[in] index
    Index of the entry of which to get the overflow indicator from
    \lt_p{values}.
@param[out] has_overflow
    <strong>On success</strong>, this function sets
    \lt_p{*has_overflow} to whether or not the entry at \lt_p{index} in
    \lt_p{values} has overflowed.

@retval #LTTNG_MAP_VALUES_STATUS_OK
    Success.
@retval #LTTNG_MAP_VALUES_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{values}
    - lttng_map_channel_get_value_type() returns
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32,
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64, or
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX
      with the map channel from which \lt_p{values} was obtained.
    - \lt_p{index} is the index of a valid key of the map channel from
      which \lt_p{values} was obtained
      (see lttng_map_channel_get_keys()).
    @lt_pre_not_null{value}

@sa lttng_map_values_signed_int_get_value_at_index() --
    Returns the value of an entry of a signed integer map values
    object.
*/
LTTNG_EXPORT extern enum lttng_map_values_status lttng_map_values_signed_int_has_overflow_at_index(
	const struct lttng_map_values *values, uint64_t index, bool *has_overflow);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_VALUES_SIGNED_INT_H */
