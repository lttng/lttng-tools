/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_KEY_H
#define LTTNG_MAP_KEY_H

#include <lttng/lttng-export.h>
#include <lttng/map/key-type.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_key
@{
*/

/*!
@struct lttng_map_key

@brief
    \lt_obj_c_map_key (opaque type).
*/
struct lttng_map_key;

/*!
@brief
    Status code for \lt_obj_map_key property accessors.
*/
enum lttng_map_key_status {
	/// Success.
	LTTNG_MAP_KEY_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_MAP_KEY_STATUS_INVALID_PARAMETER = -1,
};

/*!
@brief
    Sets \lt_p{*type} to the type of \lt_p{key}.

The type of \lt_p{key} selects which type-specific accessors apply
to it (for example, lttng_map_key_string_get_string() for the
#LTTNG_MAP_KEY_TYPE_STRING type).

@param[in] key
    Key of which to get the type.
@param[out] type
    <strong>On success</strong>, this function sets \lt_p{*type} to
    the type of \lt_p{key}.

@retval #LTTNG_MAP_KEY_STATUS_OK
    Success.
@retval #LTTNG_MAP_KEY_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{key}
    @lt_pre_not_null{type}
*/
LTTNG_EXPORT extern enum lttng_map_key_status
lttng_map_key_get_type(const struct lttng_map_key *key, enum lttng_map_key_type *type);

/*!
@brief
    Sets \lt_p{*index} to the entry index of \lt_p{key}.

Use \lt_p{*index} to address the corresponding entry in any
\c lttng_map_values produced by the map channel which owns \lt_p{key}.

@param[in] key
    Key of which to get the entry index.
@param[out] index
    <strong>On success</strong>, this function sets \lt_p{*index} to
    the entry index of \lt_p{key}.

@retval #LTTNG_MAP_KEY_STATUS_OK
    Success.
@retval #LTTNG_MAP_KEY_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{key}
    @lt_pre_not_null{index}
*/
LTTNG_EXPORT extern enum lttng_map_key_status
lttng_map_key_get_index(const struct lttng_map_key *key, uint64_t *index);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_KEY_H */
