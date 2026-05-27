/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_H
#define LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_channel
@{
*/

/*!
@brief
    Buffer ownership model of a user space \lt_obj_map_channel.

See \ref api-map-channel-buf-ownership-model "Buffer ownership model"
to learn more.
*/
enum lttng_map_channel_buffer_ownership {
	/// Per-user buffering.
	LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID = 0,

	/// Per-process buffering.
	LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID = 1,
};

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_H */
