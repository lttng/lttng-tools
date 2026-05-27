/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_H
#define LTTNG_MAP_CHANNEL_H

#include <lttng/lttng-export.h>
#include <lttng/map/channel-type.h>
#include <lttng/map/channel-update-policy.h>
#include <lttng/map/group-set.h>
#include <lttng/map/group.h>
#include <lttng/map/key-set.h>
#include <lttng/map/key-type.h>
#include <lttng/map/value-type.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_channel
@{
*/

/*!
@struct lttng_map_channel

@brief
    \lt_obj_c_map_channel (opaque type).
*/
struct lttng_map_channel;

/*!
@brief
    Status code for \lt_obj_map_channel functions.
*/
enum lttng_map_channel_status {
	/// Success.
	LTTNG_MAP_CHANNEL_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER = -1,

	/// No matching \lt_obj_map_group found.
	LTTNG_MAP_CHANNEL_STATUS_NOT_FOUND = -2,

	/// Other error.
	LTTNG_MAP_CHANNEL_STATUS_ERROR = -3,
};

/*!
@brief
    Sets \lt_p{*name} to the
    \ref api-map-channel-prop-name "name" of \lt_p{channel}.

@param[in] channel
    Map channel of which to get the name.
@param[out] name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*name} to
    the name of \lt_p{channel}.

    \lt_p{*name} remains valid as long as \lt_p{channel} exists.
    @endparblock

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{name}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_name(const struct lttng_map_channel *channel, const char **name);

/*!
@brief
    Sets \lt_p{*type} to the
    \ref api-map-channel-prop-type "type" of \lt_p{channel}.

The type of \lt_p{channel} is fixed at configuration time and selects
which type-specific accessors apply to it
(<code>lttng_map_channel_user_*</code> vs.
<code>lttng_map_channel_kernel_*</code> functions).

@param[in] channel
    Map channel of which to get the type.
@param[out] type
    <strong>On success</strong>, this function sets \lt_p{*type} to
    the type of \lt_p{channel}.

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{type}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_type(const struct lttng_map_channel *channel,
			   enum lttng_map_channel_type *type);

/*!
@brief
    Sets \lt_p{*value_type} to the
    \ref api-map-channel-prop-value-type "value type" of \lt_p{channel}.

@param[in] channel
    Map channel of which to get the value type.
@param[out] value_type
    <strong>On success</strong>, this function sets \lt_p{*value_type}
    to the value type of \lt_p{channel}.

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{value_type}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_value_type(const struct lttng_map_channel *channel,
				 enum lttng_map_value_type *value_type);

/*!
@brief
    Sets \lt_p{*max_key_count} to the
    \ref api-map-channel-prop-max-key-count "maximum key count" property
    of \lt_p{channel}.

The maximum key count caps the number of distinct keys which
\lt_p{channel} may track. It also determines the size of each contained
map.

@param[in] channel
    Map channel of which to get the maximum key count.
@param[out] max_key_count
    <strong>On success</strong>, this function sets
    \lt_p{*max_key_count} to the maximum key count of \lt_p{channel}.

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{max_key_count}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_max_key_count(const struct lttng_map_channel *channel,
				    uint64_t *max_key_count);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api-map-channel-prop-update-policy "update policy" property of
    \lt_p{channel}.

@param[in] channel
    Map channel of which to get the update policy.
@param[out] policy
    <strong>On success</strong>, this function sets \lt_p{*policy} to
    the update policy of \lt_p{channel}.

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{channel}
    @lt_pre_not_null{policy}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_update_policy(const struct lttng_map_channel *channel,
				    enum lttng_map_channel_update_policy *policy);

/* clang-format off */

/*!
@brief
    Sets \lt_p{*groups} to the \lt_obj_map_groups of \lt_p{channel}.

\lt_p{*groups} is a "snapshot" taken at call time: LTTng doesn't
update it as map groups are added to or removed from \lt_p{channel}
afterwards.

The contents of \lt_p{*groups} depend on the
\ref api-map-channel-prop-type "type" and, for a user space map
channel, the
\ref api-map-channel-buf-ownership-model "buffer ownership model" of
\lt_p{channel}:

<dl>
  <dt>\link #LTTNG_MAP_CHANNEL_TYPE_KERNEL Linux kernel\endlink map channel
  <dd>
    Exactly one #LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL group
    (the system-wide group).

    A Linux kernel map channel has \em no
    \ref api-map-channel-shared-map-group "shared map group": that's a
    user space map channel concept.

  <dt>\link #LTTNG_MAP_CHANNEL_TYPE_USER User space\endlink map channel with
      \link #LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_UID per-user buffer ownership\endlink
  <dd>
    - One #LTTNG_MAP_GROUP_TYPE_USER_PER_USER group per
      (Unix&nbsp;user,&nbsp;\ref api-map-group-prop-effective-value-type "effective&nbsp;value&nbsp;type")
      pair which has contributed to \lt_p{channel}.

    - One #LTTNG_MAP_GROUP_TYPE_SHARED group
      (the \ref api-map-channel-shared-map-group "shared map group").

  <dt>\link #LTTNG_MAP_CHANNEL_TYPE_USER User space\endlink map channel with
      \link #LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID per-process buffer ownership\endlink
  <dd>
    - One #LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS group per
      (process,&nbsp;\ref api-map-group-prop-effective-value-type "effective&nbsp;value&nbsp;type")
      pair which has contributed to \lt_p{channel}.

    - One #LTTNG_MAP_GROUP_TYPE_SHARED group
      (the \ref api-map-channel-shared-map-group "shared map group").
</dl>

A user space map channel always has a
\ref api-map-channel-shared-map-group "shared map group"
(#LTTNG_MAP_GROUP_TYPE_SHARED), regardless of its buffer ownership
model; a Linux kernel map channel never has one. When it exists, reach
it directly without iterating \lt_p{*groups} with
lttng_map_channel_get_shared_group().

Use lttng_map_group_get_type() on each member of \lt_p{*groups} to
classify it before calling type-specific accessors:
lttng_map_group_user_get_owner_id() and
lttng_map_group_user_get_owner_name() only apply to a map group whose
\ref api-map-group-prop-type "type" is
#LTTNG_MAP_GROUP_TYPE_USER_PER_USER or
#LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS.
lttng_map_group_get_effective_value_type() applies to a map group of any
type.

@param[in] channel
    Map channel of which to get the map groups.
@param[out] groups
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*groups} to
    the set of every map group of \lt_p{channel}.

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
    @lt_pre_not_null{groups}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_groups(const struct lttng_map_channel *channel,
			     struct lttng_map_group_set **groups);

/* clang-format on */

/*!
@brief
    Sets \lt_p{*group} to the
    \ref api-map-channel-shared-map-group "shared map group" of
    \lt_p{channel}.

A shared map group is a user space map channel concept: a Linux kernel
map channel never has one. Therefore this function only applies to a
user space map channel, which has exactly one shared map group: a
single, channel-wide group with no owner ID (no Unix user, no process)
and no per-partition decomposition.

The \ref api-map-group-prop-type "type" of \lt_p{*group} is always
#LTTNG_MAP_GROUP_TYPE_SHARED.

The shared map group is the destination of dead-process map values
when the \ref api-map-channel-prop-dead-group-policy "dead group policy" of
\lt_p{channel} is #LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED.

The session daemon (see \lt_man{lttng-sessiond,8}) may also write to it
directly to record values which don't originate from a tracer.

@param[in] channel
    Map channel of which to get the shared map group.
@param[out] group
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*group} to
    the shared map group of \lt_p{channel}.

    Destroy \lt_p{*group} with lttng_map_group_destroy().
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
    @lt_pre_not_null{group}

@sa lttng_map_channel_get_groups() --
    Returns the set of all map groups of a map channel, including the
    shared map group of a user space map channel.
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_shared_group(const struct lttng_map_channel *channel,
				   struct lttng_map_group **group);

/*!
@brief
    Sets \lt_p{*keys} to the current set of keys of \lt_p{channel}.

The mapping from key to index lives at the channel level: every map
(per-partition view) which \lt_p{channel} manages exposes the same set of
values at the same indices. Use \lt_p{*keys} to enumerate the keys of
\lt_p{channel} or to look up the index of a specific key, then use that
index against any \c lttng_map_values obtained from a map of
\lt_p{channel}.

\lt_p{*keys} is a "snapshot" taken at call time: the connected session
daemon returns the keys which \lt_p{channel} tracks at that moment, and
LTTng doesn't update \lt_p{*keys} as keys are added to \lt_p{channel}
afterwards.

@param[in] channel
    Map channel of which to get the keys.
@param[out] keys
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*keys} to
    the resulting set of keys.

    Destroy \lt_p{*keys} with lttng_map_key_set_destroy().
    @endparblock

@retval #LTTNG_MAP_CHANNEL_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_conn
    @lt_pre_not_null{channel}
    @lt_pre_not_null{keys}
*/
LTTNG_EXPORT extern enum lttng_map_channel_status
lttng_map_channel_get_keys(const struct lttng_map_channel *channel,
			   struct lttng_map_key_set **keys);

/*!
@brief
    Destroys the \lt_obj_map_channel \lt_p{channel}.

This function destroys the local, client-side handle on
\lt_p{channel}: it does \em not destroy the corresponding session daemon
map channel.

Only use this function to release a map channel handle which you
obtained from lttng_session_get_map_channel_by_name(). For channels
owned by a map channel set, call
lttng_map_channel_set_destroy() instead.

@param[in] channel
    @parblock
    Map channel to destroy.

    May be \c NULL, in which case this function does nothing.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_map_channel_destroy(struct lttng_map_channel *channel);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_H */
