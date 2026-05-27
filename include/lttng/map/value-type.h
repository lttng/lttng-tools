/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_VALUE_TYPE_H
#define LTTNG_MAP_VALUE_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_value
@{
*/

/*!
@brief
    Type of the values of a \lt_obj_map.
*/
enum lttng_map_value_type {
	/// 32-bit signed integer.
	LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32,

	/// 64-bit signed integer.
	LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64,

	/*!
	@brief
	    Signed integer with the native width of the session daemon
	    process.

	With this value type, the map channel uses 32-bit values when
	the session daemon runs as a 32-bit process, and 64-bit values
	when it runs as a 64-bit process.

	@attention
	    As of LTTng&nbsp;\lt_version, a map channel with this value
	    type is \em not accessible from instrumented 32-bit
	    applications when the session daemon runs as a 64-bit
	    process. If you need the map channel to be accessible from
	    both instrumented 32-bit and 64-bit applications, use
	    #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 instead.
	*/
	LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX,
};

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_VALUE_TYPE_H */
