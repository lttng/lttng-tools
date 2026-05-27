/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_UPDATE_POLICY_H
#define LTTNG_MAP_CHANNEL_UPDATE_POLICY_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_channel
@{
*/

/*!
@brief
    Update policy of a \lt_obj_map_channel.
*/
enum lttng_map_channel_update_policy {
	/// Per matching event.
	LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT = 0,

	/// Per event rule match.
	LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_RULE_MATCH = 1,
};

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_UPDATE_POLICY_H */
