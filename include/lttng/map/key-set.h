/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_KEY_SET_H
#define LTTNG_MAP_KEY_SET_H

#include <lttng/lttng-export.h>
#include <lttng/map/key.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_key
@{
*/

/*!
@struct lttng_map_key_set

@brief
    Immutable set of \lt_obj_map_keys (opaque type).
*/
struct lttng_map_key_set;

/*!
@brief
    Status code for \lt_obj_map_key set functions.
*/
enum lttng_map_key_set_status {
	/// Success.
	LTTNG_MAP_KEY_SET_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER = -1,

	/// No matching \lt_obj_map_key found.
	LTTNG_MAP_KEY_SET_STATUS_NOT_FOUND = -2,
};

/*!
@brief
    Sets \lt_p{*type} to the key type of \lt_p{set}.

All keys in \lt_p{set} share this type, which selects which
type-specific accessors apply (for example,
lttng_map_key_set_string_get_key_by_string() for the
#LTTNG_MAP_KEY_TYPE_STRING type).

@param[in] set
    Key set of which to get the key type.
@param[out] type
    <strong>On success</strong>, this function sets \lt_p{*type} to
    the key type of \lt_p{set}.

@retval #LTTNG_MAP_KEY_SET_STATUS_OK
    Success.
@retval #LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    @lt_pre_not_null{type}
*/
LTTNG_EXPORT extern enum lttng_map_key_set_status
lttng_map_key_set_get_type(const struct lttng_map_key_set *set, enum lttng_map_key_type *type);

/*!
@brief
    Sets \lt_p{*count} to the number of keys in \lt_p{set}.

@param[in] set
    Key set of which to get the number of keys.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count} to
    the number of keys in \lt_p{set}.

@retval #LTTNG_MAP_KEY_SET_STATUS_OK
    Success.
@retval #LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    @lt_pre_not_null{count}

@sa lttng_map_key_set_get_at_index() --
    Returns a key at a given index from a map key set.
*/
LTTNG_EXPORT extern enum lttng_map_key_set_status
lttng_map_key_set_get_count(const struct lttng_map_key_set *set, uint64_t *count);

/*!
@brief
    Sets \lt_p{*key} to the key at index \lt_p{index} in \lt_p{set}.

@param[in] set
    Key set of which to get a key.
@param[in] index
    Index of the key to get from \lt_p{set}.
@param[out] key
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*key} to
    the key at \lt_p{index} in \lt_p{set}.

    \lt_p{set} owns \lt_p{*key}, which remains valid as long as
    \lt_p{set} exists.
    @endparblock

@retval #LTTNG_MAP_KEY_SET_STATUS_OK
    Success.
@retval #LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    - \lt_p{index} is less than the number of keys in \lt_p{set}, as
      returned by lttng_map_key_set_get_count().
    @lt_pre_not_null{key}

@sa lttng_map_key_set_get_count() --
    Returns the number of keys in a map key set.
*/
LTTNG_EXPORT extern enum lttng_map_key_set_status lttng_map_key_set_get_at_index(
	const struct lttng_map_key_set *set, uint64_t index, const struct lttng_map_key **key);

/*!
@brief
    Destroys the \lt_obj_map_key set \lt_p{set}.

@param[in] set
    @parblock
    Map key set to destroy.

    May be \c NULL, in which case this function does nothing.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_map_key_set_destroy(struct lttng_map_key_set *set);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_KEY_SET_H */
