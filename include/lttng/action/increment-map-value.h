/*
 * SPDX-FileCopyrightText: 2023 Philippe Proulx <pproulx@efficios.com>
 * SPDX-FileCopyrightText: 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_ACTION_INCREMENT_MAP_VALUE_H
#define LTTNG_ACTION_INCREMENT_MAP_VALUE_H

#include <lttng/action/action.h>
#include <lttng/action/key-template.h>
#include <lttng/lttng-export.h>
#include <lttng/map/channel-type.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_action_incr_map_val
@{
*/

/*!
@brief
    Creates an initial “increment map value” trigger action.

On success, the returned trigger action isn't valid yet; you must
set, with the corresponding setters:

- The target \lt_obj_session name.
- The target \ref api_map_channel "map channel" name.
- The target map channel type (#LTTNG_MAP_CHANNEL_TYPE_KERNEL or
  #LTTNG_MAP_CHANNEL_TYPE_USER).
- The \ref api_trigger_action_incr_map_val_key_template "key template".

@returns
    @parblock
    Trigger action with the type
    #LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE on success,
    or \c NULL on error.

    Destroy the returned trigger action with
    lttng_action_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_action *lttng_action_increment_map_value_create(void);

/*!
@brief
    Sets the target \lt_obj_session name of the
    “increment map value” trigger action \lt_p{action} to
    \lt_p{session_name}.

LTTng finds the recording session which contains the target
\ref api_map_channel "map channel" <em>by name</em> when it executes
\lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to set the target
    recording session name.
@param[in] session_name
    Target recording session name of \lt_p{action} (copied).

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_ACTION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{session_name}

@sa lttng_action_increment_map_value_get_target_session_name() --
    Get the target recording session name of an
    “increment map value” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_set_target_session_name(struct lttng_action *action,
							 const char *session_name);

/*!
@brief
    Sets \lt_p{*session_name} to the target \lt_obj_session name of the
    “increment map value” trigger action \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to get the target
    recording session name.
@param[out] session_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*session_name}
    to the target recording session name of \lt_p{action}.

    \lt_p{action} owns \lt_p{*session_name}, which remains valid until
    the next setter call with \lt_p{action}.
    @endparblock

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_UNSET
    The target recording session name of \lt_p{action} is not set.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{session_name}

@sa lttng_action_increment_map_value_set_target_session_name() --
    Set the target recording session name of an
    “increment map value” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_get_target_session_name(const struct lttng_action *action,
							 const char **session_name);

/*!
@brief
    Sets the target \ref api_map_channel "map channel" name of the
    “increment map value” trigger action \lt_p{action} to
    \lt_p{channel_name}.

LTTng finds the target map channel <em>by name</em>, within the
\link lttng_action_increment_map_value_set_target_session_name() target
recording session\endlink, when it executes \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to set the target
    map channel name.
@param[in] channel_name
    Target map channel name of \lt_p{action} (copied).

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_ACTION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{channel_name}

@sa lttng_action_increment_map_value_get_target_channel_name() --
    Get the target map channel name of an
    “increment map value” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_set_target_channel_name(struct lttng_action *action,
							 const char *channel_name);

/*!
@brief
    Sets \lt_p{*channel_name} to the target
    \ref api_map_channel "map channel" name of the
    “increment map value” trigger action \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to get the target
    map channel name.
@param[out] channel_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*channel_name}
    to the target map channel name of \lt_p{action}.

    \lt_p{action} owns \lt_p{*channel_name}, which remains valid until
    the next setter call with \lt_p{action}.
    @endparblock

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_UNSET
    The target map channel name of \lt_p{action} is not set.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{channel_name}

@sa lttng_action_increment_map_value_set_target_channel_name() --
    Set the target map channel name of an
    “increment map value” trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_get_target_channel_name(const struct lttng_action *action,
							 const char **channel_name);

/*!
@brief
    Sets the target \ref api_map_channel "map channel" type of the
    “increment map value” trigger action \lt_p{action} to \lt_p{type}.

The target type selects which tracer owns the target map channel: a
given map channel name may exist as both a
\link #LTTNG_MAP_CHANNEL_TYPE_KERNEL Linux kernel\endlink and a
\link #LTTNG_MAP_CHANNEL_TYPE_USER user space\endlink map channel
within the
\link lttng_action_increment_map_value_set_target_session_name() target
recording session\endlink,
therefore the type disambiguates the
lookup LTTng performs when it executes \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to set the target
    map channel type.
@param[in] type
    Target map channel type of \lt_p{action}.

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}

@sa lttng_action_increment_map_value_get_target_channel_type() --
    Get the target map channel type of an “increment map value”
    trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_set_target_channel_type(struct lttng_action *action,
							 enum lttng_map_channel_type type);

/*!
@brief
    Sets \lt_p{*type} to the target \ref api_map_channel "map channel"
    type of the “increment map value” trigger action \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to get the target
    map channel type.
@param[out] type
    <strong>On success</strong>, this function sets \lt_p{*type} to
    the target map channel type of \lt_p{action}.

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_UNSET
    The target map channel type of \lt_p{action} is not set.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{type}

@sa lttng_action_increment_map_value_set_target_channel_type() --
    Set the target map channel type of an “increment map value”
    trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_get_target_channel_type(const struct lttng_action *action,
							 enum lttng_map_channel_type *type);

/*!
@brief
    Sets the \ref api_trigger_action_incr_map_val_key_template "key template"
    of the “increment map value” trigger action \lt_p{action} to
    a copy of \lt_p{key_template}.

See \ref api_trigger_action_incr_map_val_key_template for details.

Build a key template from a template string
with lttng_key_template_create_from_string().

@param[in] action
    “Increment map value” trigger action of which to set the key
    template.
@param[in] key_template
    Key template to copy into \lt_p{action}.

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_ACTION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{key_template}

@sa lttng_action_increment_map_value_get_key_template() --
    Get the key template of an
    “increment map value” trigger action.
@sa lttng_key_template_create_from_string() --
    Build a key template from a template string.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_set_key_template(struct lttng_action *action,
						  const struct lttng_key_template *key_template);

/*!
@brief
    Sets \lt_p{*key_template} to the
    \ref api_trigger_action_incr_map_val_key_template "key template"
    of the “increment map value” trigger action \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to get the key
    template.
@param[out] key_template
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*key_template}
    to the key template of \lt_p{action}.

    \lt_p{action} owns \lt_p{*key_template}, which remains valid until
    the next setter call with \lt_p{action}.
    @endparblock

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_UNSET
    The key template of \lt_p{action} is not set.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{key_template}

@sa lttng_action_increment_map_value_set_key_template() --
    Set the key template of an
    “increment map value” trigger action.
@sa lttng_key_template_to_string() --
    Render a key template back to its string form.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_get_key_template(const struct lttng_action *action,
						  const struct lttng_key_template **key_template);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_INCREMENT_MAP_VALUE_H */
