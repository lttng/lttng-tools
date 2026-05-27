/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_GROUP_H
#define LTTNG_MAP_GROUP_H

#include <lttng/lttng-export.h>
#include <lttng/map/group-type.h>
#include <lttng/map/value-type.h>
#include <lttng/map/values-set.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_group
@{
*/

/*!
@struct lttng_map_group

@brief
    \lt_obj_c_map_group (opaque type).
*/
struct lttng_map_group;

/*!
@brief
    Status code for \lt_obj_map_group functions.
*/
enum lttng_map_group_status {
	/// Success.
	LTTNG_MAP_GROUP_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER = -1,

	/// Other error.
	LTTNG_MAP_GROUP_STATUS_ERROR = -2,
};

/*!
@brief
    Sets \lt_p{*type} to the
    \ref api-map-group-prop-type "type" of \lt_p{group}.

The type of \lt_p{group} selects which type-specific accessors apply
to it:

<dl>
  <dt>#LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL
  <dd>
    No type-specific accessor applies.

  <dt>#LTTNG_MAP_GROUP_TYPE_USER_PER_USER
  <dt>#LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS
  <dd>
    - lttng_map_group_user_get_owner_id()
    - lttng_map_group_user_get_owner_name()

  <dt>#LTTNG_MAP_GROUP_TYPE_SHARED
  <dd>
    No type-specific accessor applies.

    In addition, lttng_map_values_get_partition_id() doesn't apply to
    any \lt_obj_map_values which lttng_map_group_get_values() produces
    from \lt_p{group}.
</dl>

@param[in] group
    Map group of which to get the type.
@param[out] type
    <strong>On success</strong>, this function sets \lt_p{*type} to
    the type of \lt_p{group}.

@retval #LTTNG_MAP_GROUP_STATUS_OK
    Success.
@retval #LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{group}
    @lt_pre_not_null{type}
*/
LTTNG_EXPORT extern enum lttng_map_group_status
lttng_map_group_get_type(const struct lttng_map_group *group, enum lttng_map_group_type *type);

/*!
@brief
    Sets \lt_p{*owner_id} to the owner ID of the user space map group
    \lt_p{group}.

The owner ID of \lt_p{group} depends on its \ref api-map-group-prop-type "type":

<dl>
  <dt>#LTTNG_MAP_GROUP_TYPE_USER_PER_USER
  <dd>The Unix user ID of \lt_p{group}.

  <dt>#LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS
  <dd>The process ID of \lt_p{group}.
</dl>

@param[in] group
    User space map group of which to get the owner ID.
@param[out] owner_id
    <strong>On success</strong>, this function sets \lt_p{*owner_id} to
    the owner ID of \lt_p{group}.

@retval #LTTNG_MAP_GROUP_STATUS_OK
    Success.
@retval #LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{group}
    - lttng_map_group_get_type() returns
      #LTTNG_MAP_GROUP_TYPE_USER_PER_USER or
      #LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS with \lt_p{group}.
    @lt_pre_not_null{owner_id}

@sa lttng_map_group_user_get_owner_name() --
    Returns the owner name of a user space map group.
*/
LTTNG_EXPORT extern enum lttng_map_group_status
lttng_map_group_user_get_owner_id(const struct lttng_map_group *group, uint64_t *owner_id);

/*!
@brief
    Sets \lt_p{*owner_name} to the owner name of the user space map
    group \lt_p{group}.

The owner name of \lt_p{group} is a human-readable name for its owner,
for example a Unix user name (for a
#LTTNG_MAP_GROUP_TYPE_USER_PER_USER group) or a process/command name
(for a #LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS group).

@note
    @parblock
    This API makes \em no guarantee about this name: it's provided
    for display and informational purposes only.

    In particular, the name isn't guaranteed to be set (it may be an
    empty string), to be unique amongst the \lt_obj_map_groups of a
    given \lt_obj_map_channel, nor to remain stable across calls and versions.

    Use lttng_map_group_user_get_owner_id() to identify the owner of
    \lt_p{group} reliably.
    @endparblock

@param[in] group
    User space map group of which to get the owner name.
@param[out] owner_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*owner_name}
    to the owner name of \lt_p{group}.

    \lt_p{group} owns \lt_p{*owner_name}: it remains valid as long as
    \lt_p{group} exists.
    @endparblock

@retval #LTTNG_MAP_GROUP_STATUS_OK
    Success.
@retval #LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{group}
    - lttng_map_group_get_type() returns
      #LTTNG_MAP_GROUP_TYPE_USER_PER_USER or
      #LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS with \lt_p{group}.
    @lt_pre_not_null{owner_name}

@sa lttng_map_group_user_get_owner_id() --
    Returns the owner ID of a user space map group.
*/
LTTNG_EXPORT extern enum lttng_map_group_status
lttng_map_group_user_get_owner_name(const struct lttng_map_group *group, const char **owner_name);

/*!
@brief
    Sets \lt_p{*value_type} to the effective value type of \lt_p{group}.

The effective value type of \lt_p{group} is the concrete signed integer
type (as of LTTng-tools&nbsp;\lt_version_maj_min) of its
\lt_obj_map_values, resolved from the
\ref api-map-channel-prop-value-type "value type" of the
\lt_obj_map_channel of \lt_p{group}.

As of LTTng&nbsp;\lt_version, the effective value type of a map group is
always #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 or
#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64: it's never
#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX, which the session daemon resolves
to a concrete width when it creates the maps of the group.

A user space map channel having the
#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX value type can expose, for a single
owner, both a #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 and a
#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64 map group: the instrumented
applications of the owner contribute to the group of their own bitness.
A channel having the #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 or
#LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64 value type
exposes a single group per owner:
all the applications of the owner, whatever their bitness, contribute to
the same map group.

@param[in] group
    Map group of which to get the effective value type.
@param[out] value_type
    <strong>On success</strong>, this function sets \lt_p{*value_type}
    to the effective value type of \lt_p{group}.

@retval #LTTNG_MAP_GROUP_STATUS_OK
    Success.
@retval #LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{group}
    @lt_pre_not_null{value_type}
*/
LTTNG_EXPORT extern enum lttng_map_group_status
lttng_map_group_get_effective_value_type(const struct lttng_map_group *group,
					 enum lttng_map_value_type *value_type);

/*!
@brief
    Sets \lt_p{*values_set} to the current \lt_obj_map_values of \lt_p{group}.

\lt_p{*values_set} contains one
\link lttng_map_values per-partition values object\endlink per
partition which contributes to \lt_p{group}.

When the \ref api-map-group-prop-type "type" of \lt_p{group} is
#LTTNG_MAP_GROUP_TYPE_SHARED, the
\ref api-map-channel-shared-map-group "shared map group" has no
per-partition decomposition: \lt_p{*values_set} always contains exactly
one \lt_obj_map_values, and lttng_map_values_get_partition_id() does
\em not apply to it.

@important
    @parblock
    This function does \em not provide an atomic snapshot of the map
    values: the connected session daemon reads the values one by one,
    and LTTng tracers may concurrently update any of them while the
    function runs. Therefore, \lt_p{*values_set} doesn't necessarily
    reflect the state of the maps at a \em single instant.

    To obtain a consistent view of the map values, either:

    - Stop the recording session with lttng_stop_tracing() before
      calling this function.

    - \link lttng_disable_event() Disable the recording event
      rules\endlink and/or
      \link lttng_unregister_trigger() remove the triggers\endlink
      having an
      \link api_trigger_action_incr_map_val "increment map value"\endlink
      action which targets the map channel of \lt_p{group}.
    @endparblock

@param[in] group
    Map group of which to snapshot the per-partition views.
@param[out] values_set
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*values_set} to the resulting collection of per-partition
    views.

    Destroy \lt_p{*values_set} with lttng_map_values_set_destroy().
    @endparblock

@retval #LTTNG_MAP_GROUP_STATUS_OK
    Success.
@retval #LTTNG_MAP_GROUP_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.
@retval #LTTNG_MAP_GROUP_STATUS_ERROR
    Other error.

@pre
    @lt_pre_conn
    @lt_pre_not_null{group}
    @lt_pre_not_null{values_set}
*/
LTTNG_EXPORT extern enum lttng_map_group_status
lttng_map_group_get_values(const struct lttng_map_group *group,
			   struct lttng_map_values_set **values_set);

/*!
@brief
    Destroys the \lt_obj_map_group \lt_p{group}.

This function destroys the local, client-side handle on \lt_p{group}: it
does \em not destroy the corresponding session daemon map group.

Only use this function to release a map group handle which you obtained
from lttng_map_channel_get_shared_group(),
lttng_map_channel_user_get_group_by_uid(), or
lttng_map_channel_user_get_group_by_pid(). For groups owned by a map
group set, call lttng_map_group_set_destroy() instead.

@param[in] group
    @parblock
    Map group to destroy.

    May be \c NULL, in which case this function does nothing.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_map_group_destroy(struct lttng_map_group *group);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_GROUP_H */
