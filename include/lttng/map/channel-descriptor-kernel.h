/*
 * Copyright (C) 2024 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_DESCRIPTOR_KERNEL_H
#define LTTNG_MAP_CHANNEL_DESCRIPTOR_KERNEL_H

#include <lttng/lttng-export.h>
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
    Creates a descriptor of a Linux kernel \lt_obj_map_channel whose
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
    <td>#LTTNG_MAP_CHANNEL_TYPE_KERNEL
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
    <td>\ref api-map-channel-prop-max-key-count "Maximum key count"
    <td>\lt_def_map_channel_max_key_count
    <td>lttng_map_channel_descriptor_set_max_key_count()
  <tr>
    <td>\ref api-map-channel-prop-update-policy "Update policy"
    <td>#LTTNG_MAP_CHANNEL_UPDATE_POLICY_PER_EVENT
    <td>lttng_map_channel_descriptor_set_update_policy()
</table>

@param[in] value_type
    Value type of the map entries of the described map channel.

@returns
    @parblock
    Linux kernel map channel descriptor on success, or \c NULL on error.

    Destroy the returned descriptor with
    lttng_map_channel_descriptor_destroy().
    @endparblock

@pre
    - \lt_p{value_type} is one of #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32,
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64, or
      #LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX.

@sa lttng_map_channel_descriptor_user_string_key_scalar_value_create() --
    Creates a descriptor of a user space map channel whose maps have
    string keys and scalar values.
*/
LTTNG_EXPORT extern struct lttng_map_channel_descriptor *
lttng_map_channel_descriptor_kernel_string_key_scalar_value_create(
	enum lttng_map_value_type value_type);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_DESCRIPTOR_KERNEL_H */
