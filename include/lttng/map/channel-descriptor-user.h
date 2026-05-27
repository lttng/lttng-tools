/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_DESCRIPTOR_USER_H
#define LTTNG_MAP_CHANNEL_DESCRIPTOR_USER_H

#include <lttng/lttng-export.h>
#include <lttng/map/channel-buffer-ownership.h>
#include <lttng/map/channel-dead-group-policy.h>
#include <lttng/map/channel-descriptor.h>
#include <lttng/map/value-type.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_map_channel
@{
*/

/*!
@brief
    Creates a descriptor of a user space \lt_obj_map_channel whose
    \lt_obj_maps have string keys and scalar values.

On success, the returned descriptor has the following initial
properties:

<table>
  <tr>
    <th>Property
    <th>Value
    <th>Setter
  <tr>
    <td>\ref api-map-channel-prop-name "Name"
    <td>Unset
    <td>lttng_map_channel_descriptor_set_name()
  <tr>
    <td>\ref api-map-channel-prop-type "Type"
    <td>#LTTNG_MAP_CHANNEL_TYPE_USER
    <td>Not applicable
  <tr>
    <td>\ref api-map-channel-prop-key-type "Key type"
    <td>#LTTNG_MAP_KEY_TYPE_STRING
    <td>Not applicable
  <tr>
    <td>\ref api-map-channel-prop-value-type "Value type"
    <td>\lt_p{value_type}
    <td>Not applicable
  <tr>
    <td>\ref api-map-channel-prop-buf-ownership "Buffer ownership model"
    <td>\lt_p{ownership_model}
    <td>Not applicable
  <tr>
    <td>\ref api-map-channel-prop-max-key-count "Maximum key count"
    <td>\lt_def_map_channel_max_key_count
    <td>lttng_map_channel_descriptor_set_max_key_count()
  <tr>
    <td>\ref api-map-channel-prop-update-policy "Update policy"
    <td>#LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT
    <td>lttng_map_channel_descriptor_set_update_policy()
  <tr>
    <td>\ref api-map-channel-prop-dead-group-policy "Dead group policy"
    <td>#LTTNG_MAP_CHANNEL_DEAD_GROUP_POLICY_SUM_INTO_SHARED
    <td>lttng_map_channel_descriptor_user_set_dead_group_policy()
</table>

@param[in] value_type
    Value type of the map entries of the described map channel.
@param[in] ownership_model
    Buffer ownership model of the described map channel.

@returns
    @parblock
    User space map channel descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_map_channel_descriptor_destroy().
    @endparblock

@pre
    - \lt_p{value_type} is one of #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32,
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64, or
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX.

@sa lttng_map_channel_descriptor_kernel_string_key_scalar_value_create() --
    Creates a descriptor of a kernel map channel whose maps have
    string keys and scalar values.
*/
LTTNG_EXPORT extern struct lttng_map_channel_descriptor *
lttng_map_channel_descriptor_user_string_key_scalar_value_create(
	enum lttng_map_value_type value_type,
	enum lttng_map_channel_buffer_ownership ownership_model);

/*!
@brief
    Sets \lt_p{*ownership_model} to the
    \ref api-map-channel-prop-buf-ownership "buffer ownership model" of
    the user space map channel described by \lt_p{descriptor}.

@param[in] descriptor
    Descriptor of which to get the buffer ownership model of the
    described user space map channel.
@param[out] ownership_model
    <strong>On success</strong>, this function sets
    \lt_p{*ownership_model} to the buffer ownership model of the
    described map channel.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    - lttng_map_channel_descriptor_get_type() returns
      #LTTNG_MAP_CHANNEL_TYPE_USER with \lt_p{descriptor}.
    @lt_pre_not_null{ownership_model}
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_user_get_buffer_ownership(
	const struct lttng_map_channel_descriptor *descriptor,
	enum lttng_map_channel_buffer_ownership *ownership_model);

/*!
@brief
    Sets the
    \ref api-map-channel-prop-dead-group-policy "dead group policy" property
    of the user space map channel described by \lt_p{descriptor} to
    \lt_p{policy}.

The dead group policy controls what LTTng does with the values of the
\lt_obj_maps of an instrumented process when this process terminates
while the described map channel still exists. It only applies to a
user space map channel whose
\ref api-map-channel-buf-ownership-model "buffer ownership model" is
#LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID.

@param[in] descriptor
    Descriptor of which to set the dead group policy of the
    described user space map channel to \lt_p{policy}.
@param[in] policy
    Dead group policy property to set.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    - lttng_map_channel_descriptor_get_type() returns
      #LTTNG_MAP_CHANNEL_TYPE_USER with \lt_p{descriptor}.
    - lttng_map_channel_descriptor_user_get_buffer_ownership() returns
      #LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID with \lt_p{descriptor}.

@sa lttng_map_channel_descriptor_user_get_dead_group_policy() --
    Returns the dead group policy of the described user space map
    channel of a map channel descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_user_set_dead_group_policy(
	struct lttng_map_channel_descriptor *descriptor,
	enum lttng_map_channel_dead_group_policy policy);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api-map-channel-prop-dead-group-policy "dead group policy" property
    of the user space map channel described by \lt_p{descriptor}.

@param[in] descriptor
    Descriptor of which to get the dead group policy of the
    described user space map channel.
@param[out] policy
    <strong>On success</strong>, this function sets \lt_p{*policy} to
    the dead group policy of the described map channel.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    - lttng_map_channel_descriptor_get_type() returns
      #LTTNG_MAP_CHANNEL_TYPE_USER with \lt_p{descriptor}.
    - lttng_map_channel_descriptor_user_get_buffer_ownership() returns
      #LTTNG_MAP_CHANNEL_BUFFER_OWNERSHIP_PER_PID with \lt_p{descriptor}.
    @lt_pre_not_null{policy}

@sa lttng_map_channel_descriptor_user_set_dead_group_policy() --
    Sets the dead group policy of the described user space map channel
    of a map channel descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_user_get_dead_group_policy(
	const struct lttng_map_channel_descriptor *descriptor,
	enum lttng_map_channel_dead_group_policy *policy);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_DESCRIPTOR_USER_H */
