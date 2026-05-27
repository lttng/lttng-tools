/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_VALUES_H
#define LTTNG_MAP_VALUES_H

#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_value
@{
*/

/*!
@struct lttng_map_values

@brief
    Per-partition \lt_obj_map_values (opaque type).
*/
struct lttng_map_values;

/*!
@brief
    Status code for \lt_obj_map_values functions.
*/
enum lttng_map_values_status {
	/// Success.
	LTTNG_MAP_VALUES_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_MAP_VALUES_STATUS_INVALID_PARAMETER = -1,
};

/*!
@brief
    Sets \lt_p{*partition_id} to the partition ID which \lt_p{values}
    corresponds to within the partitioning of its parent group.

This function does \em not apply to a \lt_obj_map_values produced by a
\ref api-map-channel-shared-map-group "shared map group" (a map group
of type #LTTNG_MAP_GROUP_TYPE_SHARED), which has no per-partition
decomposition.

@param[in] values
    Map values object of which to get the partition ID.
@param[out] partition_id
    <strong>On success</strong>, this function sets
    \lt_p{*partition_id} to the partition ID of \lt_p{values}.

@retval #LTTNG_MAP_VALUES_STATUS_OK
    Success.
@retval #LTTNG_MAP_VALUES_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{values}
    - The \ref api-map-group-prop-type "type" of the map group which
      produced \lt_p{values} is \em not #LTTNG_MAP_GROUP_TYPE_SHARED.
    @lt_pre_not_null{partition_id}
*/
LTTNG_EXPORT extern enum lttng_map_values_status
lttng_map_values_get_partition_id(const struct lttng_map_values *values,
				  unsigned int *partition_id);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_VALUES_H */
