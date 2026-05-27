/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_KEY_STRING_H
#define LTTNG_MAP_KEY_STRING_H

#include <lttng/lttng-export.h>
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
    Sets \lt_p{*str} to the string of the string \lt_obj_map_key
    \lt_p{key}.

@param[in] key
    String key of which to get the string.
@param[out] str
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*str} to
    the string of \lt_p{key}.

    \lt_p{key} owns \lt_p{*str}, which remains valid as long as
    \lt_p{key} exists.
    @endparblock

@retval #LTTNG_MAP_KEY_STATUS_OK
    Success.
@retval #LTTNG_MAP_KEY_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{key}
    - lttng_map_key_get_type() returns #LTTNG_MAP_KEY_TYPE_STRING
      with \lt_p{key}.
    @lt_pre_not_null{str}
*/
LTTNG_EXPORT extern enum lttng_map_key_status
lttng_map_key_string_get_string(const struct lttng_map_key *key, const char **str);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_KEY_STRING_H */
