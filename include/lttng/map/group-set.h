/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_GROUP_SET_H
#define LTTNG_MAP_GROUP_SET_H

#include <lttng/lttng-export.h>
#include <lttng/map/group.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_group
@{
*/

/*!
@struct lttng_map_group_set

@brief
    Set of \lt_obj_map_groups (opaque type).
*/
struct lttng_map_group_set;

/*!
@brief
    Status code for \lt_obj_map_group set functions.
*/
enum lttng_map_group_set_status {
	/// Success.
	LTTNG_MAP_GROUP_SET_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_MAP_GROUP_SET_STATUS_INVALID_PARAMETER = -1,
};

/*!
@brief
    Sets \lt_p{*count} to the number of map groups in \lt_p{set}.

@param[in] set
    Map group set of which to get the number of map groups.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count} to
    the number of map groups in \lt_p{set}.

@retval #LTTNG_MAP_GROUP_SET_STATUS_OK
    Success.
@retval #LTTNG_MAP_GROUP_SET_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    @lt_pre_not_null{count}

@sa lttng_map_group_set_get_at_index() --
    Returns a map group at a given index from a map group set.
*/
LTTNG_EXPORT extern enum lttng_map_group_set_status
lttng_map_group_set_get_count(const struct lttng_map_group_set *set, uint64_t *count);

/*!
@brief
    Sets \lt_p{*group} to the map group at index \lt_p{index} in
    \lt_p{set}.

@param[in] set
    Map group set of which to get a map group.
@param[in] index
    Index of the map group to get from \lt_p{set}.
@param[out] group
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*group} to
    the map group at \lt_p{index} in \lt_p{set}.

    \lt_p{set} owns \lt_p{*group}, which remains valid as long as
    \lt_p{set} exists.
    @endparblock

@retval #LTTNG_MAP_GROUP_SET_STATUS_OK
    Success.
@retval #LTTNG_MAP_GROUP_SET_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    - \lt_p{index} is less than the number of map groups in \lt_p{set},
      as returned by lttng_map_group_set_get_count().
    @lt_pre_not_null{group}

@sa lttng_map_group_set_get_count() --
    Returns the number of map groups in a map group set.
*/
LTTNG_EXPORT extern enum lttng_map_group_set_status
lttng_map_group_set_get_at_index(const struct lttng_map_group_set *set,
				 uint64_t index,
				 const struct lttng_map_group **group);

/*!
@brief
    Destroys the \lt_obj_map_group set \lt_p{set}.

@param[in] set
    @parblock
    Map group set to destroy.

    May be \c NULL, in which case this function does nothing.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_map_group_set_destroy(struct lttng_map_group_set *set);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_GROUP_SET_H */
