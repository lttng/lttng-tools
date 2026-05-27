/*
 * Copyright (C) 2023 Philippe Proulx <eepp@efficios.com>
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CHANNEL_DESCRIPTOR_H
#define LTTNG_MAP_CHANNEL_DESCRIPTOR_H

#include <lttng/lttng-export.h>
#include <lttng/map/channel-type.h>
#include <lttng/map/channel-update-policy.h>
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
@struct lttng_map_channel_descriptor

@brief
    \lt_obj_c_map_channel descriptor (opaque type).
*/
struct lttng_map_channel_descriptor;

/*!
@brief
    Status code for \lt_obj_map_channel descriptor property accessors.
*/
enum lttng_map_channel_descriptor_status {
	/// Success.
	LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK = 0,

	/// Property is not set.
	LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_UNSET = 1,

	/// Unsatisfied precondition.
	LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER = -1,
};

/*!
@brief
    Sets the
    \ref api-map-channel-prop-name "name" of the map channel described
    by \lt_p{descriptor} to a copy of \lt_p{name}.

The name property of a map channel descriptor is initially unset. When
you call lttng_session_add_map_channel() with a descriptor having no
name, the \ref api-gen-sessiond-conn "session daemon" automatically
generates a name for the resulting map channel. The generated name is a
property of the map channel itself, not of \lt_p{descriptor}: retrieve
it through lttng_map_channel_get_name() with a map channel obtained from
lttng_session_list_map_channels().

@param[in] descriptor
    Descriptor of which to set the name of the described map channel
    to a copy of \lt_p{name}.
@param[in] name
    Name property to set (copied).

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    @lt_pre_not_null{name}

@sa lttng_map_channel_descriptor_get_name() --
    Returns the name of the described map channel of a map channel
    descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_set_name(struct lttng_map_channel_descriptor *descriptor,
				      const char *name);

/*!
@brief
    Sets \lt_p{*name} to the
    \ref api-map-channel-prop-name "name" of the map channel described
    by \lt_p{descriptor}.

This function returns the name property of \lt_p{descriptor} as last
set with lttng_map_channel_descriptor_set_name(), or
#LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_UNSET when that property isn't
set.

When the name property isn't set, the
\ref api-gen-sessiond-conn "session daemon" generates the name of the
resulting map channel when you call lttng_session_add_map_channel().
That generated name is a property of the map channel itself, not of
\lt_p{descriptor}: retrieve it through lttng_map_channel_get_name()
with a map channel obtained from lttng_session_list_map_channels().

@param[in] descriptor
    Descriptor of the map channel of which to get the name.
@param[out] name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*name} to
    the name of the described map channel.

    \lt_p{*name} remains valid as long as \lt_p{descriptor} exists.
    @endparblock

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_UNSET
    The name property of \lt_p{descriptor} is not set.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    @lt_pre_not_null{name}

@sa lttng_map_channel_descriptor_set_name() --
    Sets the name of the described map channel of a map channel
    descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_name(const struct lttng_map_channel_descriptor *descriptor,
				      const char **name);

/*!
@brief
    Sets \lt_p{*type} to the
    \ref api-map-channel-prop-type "type" of the map channel described
    by \lt_p{descriptor}.

The function which produced \lt_p{descriptor}
(\link lttng_map_channel_descriptor_user_string_key_scalar_value_create()
user space\endlink vs.
\link lttng_map_channel_descriptor_kernel_string_key_scalar_value_create()
kernel\endlink) determines its type, which selects which type-specific
accessors apply.

@param[in] descriptor
    Descriptor of which to get the type of the described map channel.
@param[out] type
    <strong>On success</strong>, this function sets \lt_p{*type} to
    the type of the described map channel.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    @lt_pre_not_null{type}
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_type(const struct lttng_map_channel_descriptor *descriptor,
				      enum lttng_map_channel_type *type);

/*!
@brief
    Sets \lt_p{*value_type} to the
    \ref api-map-channel-prop-value-type "value type" of the map channel
    described by \lt_p{descriptor}.

@param[in] descriptor
    Descriptor of which to get the value type of the described
    map channel.
@param[out] value_type
    <strong>On success</strong>, this function sets \lt_p{*value_type}
    to the value type of the described map channel.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    @lt_pre_not_null{value_type}
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_value_type(const struct lttng_map_channel_descriptor *descriptor,
					    enum lttng_map_value_type *value_type);

/*!
@brief
    Sets the
    \ref api-map-channel-prop-max-key-count "maximum key count" property
    of the map channel described by \lt_p{descriptor} to
    \lt_p{max_key_count}.

The maximum key count caps the number of distinct keys which
the described map channel may track. It also determines the size of
each contained map.

@param[in] descriptor
    Descriptor of which to set the maximum key
    count of the described map channel to \lt_p{max_key_count}.
@param[in] max_key_count
    Maximum key count property to set.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    - \lt_p{max_key_count} is greater than 0.

@sa lttng_map_channel_descriptor_get_max_key_count() --
    Returns the maximum key count of the described map channel of a map
    channel descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_set_max_key_count(struct lttng_map_channel_descriptor *descriptor,
					       uint64_t max_key_count);

/*!
@brief
    Sets \lt_p{*max_key_count} to the
    \ref api-map-channel-prop-max-key-count "maximum key count" property
    of the map channel described by \lt_p{descriptor}.

@param[in] descriptor
    Descriptor of which to get the maximum
    key count of the described map channel.
@param[out] max_key_count
    <strong>On success</strong>, this function sets
    \lt_p{*max_key_count} to the maximum key count of the described
    map channel.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    @lt_pre_not_null{max_key_count}

@sa lttng_map_channel_descriptor_set_max_key_count() --
    Sets the maximum key count of the described map channel of a map
    channel descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_max_key_count(
	const struct lttng_map_channel_descriptor *descriptor, uint64_t *max_key_count);

/*!
@brief
    Sets the
    \ref api-map-channel-prop-update-policy "update policy" property of
    the map channel described by \lt_p{descriptor} to \lt_p{policy}.

@param[in] descriptor
    Descriptor of which to set the update policy of the described
    map channel to \lt_p{policy}.
@param[in] policy
    Update policy property to set.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}

@sa lttng_map_channel_descriptor_get_update_policy() --
    Returns the update policy of the described map channel of a map
    channel descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_set_update_policy(struct lttng_map_channel_descriptor *descriptor,
					       enum lttng_map_channel_update_policy policy);

/*!
@brief
    Sets \lt_p{*policy} to the
    \ref api-map-channel-prop-update-policy "update policy" property of
    the map channel described by \lt_p{descriptor}.

@param[in] descriptor
    Descriptor of which to get the update policy of the described
    map channel.
@param[out] policy
    <strong>On success</strong>, this function sets \lt_p{*policy} to
    the update policy of the described map channel.

@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_OK
    Success.
@retval #LTTNG_MAP_CHANNEL_DESCRIPTOR_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{descriptor}
    @lt_pre_not_null{policy}

@sa lttng_map_channel_descriptor_set_update_policy() --
    Sets the update policy of the described map channel of a map
    channel descriptor.
*/
LTTNG_EXPORT extern enum lttng_map_channel_descriptor_status
lttng_map_channel_descriptor_get_update_policy(const struct lttng_map_channel_descriptor *descriptor,
					       enum lttng_map_channel_update_policy *policy);

/*!
@brief
    Destroys the \lt_obj_map_channel descriptor \lt_p{descriptor}.

@param[in] descriptor
    @parblock
    Map channel descriptor to destroy.

    May be \c NULL, in which case this function does nothing.
    @endparblock
*/
LTTNG_EXPORT extern void
lttng_map_channel_descriptor_destroy(struct lttng_map_channel_descriptor *descriptor);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CHANNEL_DESCRIPTOR_H */
