/*
 * Copyright (C) 2026 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_GROUP_TYPE_H
#define LTTNG_MAP_GROUP_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_group
@{
*/

/*!
@brief
    Type of a \lt_obj_map_group.

See \ref api-map-group-prop-type "Type" to learn more.
*/
enum lttng_map_group_type {
	/// Linux kernel, system-wide map group.
	LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL = 0,

	/// Per-user, user space map group.
	LTTNG_MAP_GROUP_TYPE_USER_PER_USER = 1,

	/// Per-process, user space map group.
	LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS = 2,

	/*!
	@brief
	    Channel-wide map group with no owner ID (one per user space
	    \lt_obj_map_channel).

	A Linux kernel map channel has no shared map group.

	See \ref api-map-channel-shared-map-group "Shared map group"
	to learn more.
	*/
	LTTNG_MAP_GROUP_TYPE_SHARED = 3,
};

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_GROUP_TYPE_H */
