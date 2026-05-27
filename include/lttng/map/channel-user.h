/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_USER_H
#define LTTNG_MAP_CHANNEL_USER_H

#include <lttng/lttng-export.h>
#include <lttng/map/channel-buffer-ownership.h>
#include <lttng/map/channel-dead-group-policy.h>
#include <lttng/map/channel.h>
#include <lttng/map/group-set.h>
#include <lttng/map/group.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_channel
@{
*/

/*!
@brief
    Sets \lt_p{*ownership_model} to the
    \ref api-map-channel-prop-buf-ownership "buffer ownership model" of
    the user space \lt_obj_map_channel \lt_p{channel}.

@param[in] channel
    User space map channel of which to get the buffer ownership model.
@param[out] ownership_model
    <strong>On success</strong>, this function sets
    \lt_p{*ownership_model} to the buffer ownership model of
    \lt_p{channel}.

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    - lttng_map_channel_get_type() returns
      #LTTNG_MAP_CHANNEL_TYPE_USER with \lt_p{channel}.
    @lt_pre_not_null{ownership_model}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status lttng_map_channel_user_get_buffer_ownership(
	const struct lttng_map_channel *channel,
	enum lttng_map_channel_buffer_ownership *ownership_model);

/*!
@brief
    Sets \lt_p{*groups} to the \lt_obj_map_groups of the user space
    \lt_obj_map_channel \lt_p{channel} for the Unix user ID \lt_p{uid}.

Depending on the
\ref api-map-channel-prop-value-type "value type" of \lt_p{channel},
\lt_p{*groups} contains one or two map groups for \lt_p{uid}:

<dl>
  <dt>#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32
  <dt>#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64
  <dd>
    \lt_p{*groups} contains a single map group: all the instrumented
    applications of \lt_p{uid}, whatever their bitness, contribute
    to it.

  <dt>#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX
  <dd>
    \lt_p{*groups} may contain up to two map groups, one of the
    \link lttng_map_group_get_effective_value_type() effective value
    type\endlink #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 and one of the
    effective value type #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64: the
    instrumented applications of \lt_p{uid} contribute to the map group
    of their own bitness.
</dl>

@param[in] channel
    Per-user user space map channel of which to get the map groups.
@param[in] uid
    Unix user ID of the map groups to get from \lt_p{channel}.
@param[out] groups
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*groups} to
    the map groups of \lt_p{channel} for \lt_p{uid}.

    Destroy \lt_p{*groups} with lttng_map_group_set_destroy().
    @endparblock

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.
@retval #LTTNG_MAP_CHANNEL_STATUS_ERROR
    Other error.

@pre
    @lt_pre_conn
    @lt_pre_not_null{channel}
    - lttng_map_channel_get_type() returns
      #LTTNG_MAP_CHANNEL_TYPE_USER with \lt_p{channel}.
    - lttng_map_channel_user_get_buffer_ownership() returns
      #LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID with \lt_p{channel}.
    @lt_pre_not_null{groups}

@sa lttng_map_channel_user_get_group_by_pid() --
    Returns the map groups of a user space map channel by PID.
*/
LTTNG_EXPORT extern enum lttng_map_channel_status lttng_map_channel_user_get_group_by_uid(
	const struct lttng_map_channel *channel, uid_t uid, struct lttng_map_group_set **groups);

/*!
@brief
    Sets \lt_p{*groups} to the \lt_obj_map_groups of the user space
    \lt_obj_map_channel \lt_p{channel} for the process ID \lt_p{pid}.

Depending on the
\ref api-map-channel-prop-value-type "value type" of \lt_p{channel},
\lt_p{*groups} contains one or two map groups for \lt_p{pid}:

<dl>
  <dt>#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32
  <dt>#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64
  <dd>
    \lt_p{*groups} contains a single map group.

  <dt>#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX
  <dd>
    \lt_p{*groups} may contain up to two map groups, one of the
    \link lttng_map_group_get_effective_value_type() effective value
    type\endlink #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 and one of the
    effective value type #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64.
</dl>

@param[in] channel
    Per-process user space map channel of which to get the map groups.
@param[in] pid
    Process ID of the map groups to get from \lt_p{channel}.
@param[out] groups
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*groups} to
    the map groups of \lt_p{channel} for \lt_p{pid}.

    Destroy \lt_p{*groups} with lttng_map_group_set_destroy().
    @endparblock

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.
@retval #LTTNG_MAP_CHANNEL_STATUS_ERROR
    Other error.

@pre
    @lt_pre_conn
    @lt_pre_not_null{channel}
    - lttng_map_channel_get_type() returns
      #LTTNG_MAP_CHANNEL_TYPE_USER with \lt_p{channel}.
    - lttng_map_channel_user_get_buffer_ownership() returns
      #LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID with \lt_p{channel}.
    @lt_pre_not_null{groups}

@sa lttng_map_channel_user_get_group_by_uid() --
    Returns the map groups of a user space map channel by UID.
*/
LTTNG_EXPORT extern enum lttng_map_channel_status lttng_map_channel_user_get_group_by_pid(
	const struct lttng_map_channel *channel, pid_t pid, struct lttng_map_group_set **groups);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api-map-channel-prop-dead-group-policy "dead group policy" of
    the user space \lt_obj_map_channel \lt_p{channel}.

@param[in] channel
    Per-process user space map channel of which to get the dead group
    policy.
@param[out] policy
    <strong>On success</strong>, this function sets \lt_p{*policy} to
    the dead group policy of \lt_p{channel}.

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    - lttng_map_channel_get_type() returns
      #LTTNG_MAP_CHANNEL_TYPE_USER with \lt_p{channel}.
    - lttng_map_channel_user_get_buffer_ownership() returns
      #LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID with \lt_p{channel}.
    @lt_pre_not_null{policy}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_user_get_dead_group_policy(const struct lttng_map_channel *channel,
					     enum lttng_map_channel_dead_group_policy *policy);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_USER_H */
