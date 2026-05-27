/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_KEY_SET_STRING_H
#define LTTNG_MAP_KEY_SET_STRING_H

#include <lttng/lttng-export.h>
#include <lttng/map/key-set.h>
#include <lttng/map/key.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_key
@{
*/

/*!
@brief
    Sets \lt_p{*key} to the string \lt_obj_map_key in \lt_p{set} whose
    string equals \lt_p{str}.

@param[in] set
    String key set in which to look up a key by string.
@param[in] str
    String of the key to find in \lt_p{set}.
@param[out] key
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*key} to
    the key in \lt_p{set} whose string equals \lt_p{str}.

    \lt_p{set} owns \lt_p{*key}, which remains valid as long as
    \lt_p{set} exists.
    @endparblock

@retval #LTTNG_MAP_KEY_SET_STATUS_OK
    Success.
@retval #LTTNG_MAP_KEY_SET_STATUS_NOT_FOUND
    No key in \lt_p{set} has the string \lt_p{str}.
@retval #LTTNG_MAP_KEY_SET_STATUS_INVALID_PARAMETER
    Unsatisfied precondition, including \lt_p{set} not being a set of
    string keys.

@pre
    @lt_pre_not_null{set}
    - lttng_map_key_set_get_type() returns
      #LTTNG_MAP_KEY_TYPE_STRING with \lt_p{set}.
    @lt_pre_not_null{str}
    @lt_pre_not_null{key}
*/
LTTNG_EXPORT extern enum lttng_map_key_set_status lttng_map_key_set_string_get_key_by_string(
	const struct lttng_map_key_set *set, const char *str, const struct lttng_map_key **key);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_KEY_SET_STRING_H */
