/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_KEY_TYPE_H
#define LTTNG_MAP_KEY_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_key
@{
*/

/*!
@brief
    Type of the keys of a \lt_obj_map.
 */
enum lttng_map_key_type {
	/// String key.
	LTTNG_MAP_KEY_TYPE_STRING,
};

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_KEY_TYPE_H */
