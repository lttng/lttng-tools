/*
 * Copyright (C) 2026 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_H
#define LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_channel
@{
*/

/*!
@brief
    Dead group policy of a user space \lt_obj_map_channel with the
    per-process
    \ref api-map-channel-buf-ownership-model "buffer ownership model".

See \ref api-map-channel-dead-group-policy "Dead group policy" to
learn more.
*/
enum lttng_map_channel_dead_group_policy {
	/*!
	@brief
	    Discard the maps of the terminated process.

	The values which the process accumulated since the start of the
	recording session are lost.
	*/
	LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_DROP = 0,

	/*!
	@brief
	    Add each value of each map of the terminated process to the
	    corresponding key of the
	    \ref api-map-channel-shared-map-group "shared map group" of
	    the map channel.

	When the addition would overflow the
	\ref api-map-group-prop-effective-value-type "effective value type"
	of the map group, the result wraps around (modular arithmetic)
	and LTTng sets the overflow flag of the corresponding shared map
	value (see lttng_map_values_signed_int_has_overflow_at_index()).
	*/
	LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED = 1,
};

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_H */
