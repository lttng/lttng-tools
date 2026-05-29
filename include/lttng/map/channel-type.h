/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_TYPE_H
#define LTTNG_MAP_CHANNEL_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_channel
@{
*/

/*!
@brief
    Type of a \lt_obj_map_channel.
*/
enum lttng_map_channel_type {
	/// Linux kernel map channel.
	LTTNG_MAP_CHANNEL_TYPE_KERNEL = 0,

	/// User space map channel.
	LTTNG_MAP_CHANNEL_TYPE_USER = 1,
};

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_TYPE_H */
