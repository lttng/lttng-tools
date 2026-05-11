/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <eepp@efficios.com>
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_INCREMENT_MAP_VALUE_H
#define LTTNG_ACTION_INCREMENT_MAP_VALUE_H

#include <lttng/action/action.h>
#include <lttng/action/key-template.h>
#include <lttng/domain.h>
#include <lttng/lttng-export.h>

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
- The target tracing domain (#LTTNG_DOMAIN_KERNEL or #LTTNG_DOMAIN_UST).
- The target \ref api_map_channel "map channel" name.
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
    to the target recording session name of \lt_p{action}, or to
    \c NULL if unset.

    \lt_p{action} owns \lt_p{*session_name}, which remains valid until
    the next setter call with \lt_p{action}.
    @endparblock

@returns
    Target recording session name of \lt_p{action}, or \c NULL if unset.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}

@sa lttng_action_increment_map_value_set_target_session_name() --
    Set the target recording session name of an
    “increment map value” trigger action.
*/
LTTNG_EXPORT extern const char *
lttng_action_increment_map_value_get_target_session_name(const struct lttng_action *action);

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
    Returns the target \ref api_map_channel "map channel" name of the
    “increment map value” trigger action \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to get the target
    map channel name.

@returns
    @parblock
    Target map channel name of \lt_p{action}, or \c NULL if unset.

    \lt_p{action} owns the returned string, which remains valid until
    the next setter call with \lt_p{action}.
    @endparblock

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}

@sa lttng_action_increment_map_value_set_target_channel_name() --
    Set the target map channel name of an
    “increment map value” trigger action.
*/
LTTNG_EXPORT extern const char *
lttng_action_increment_map_value_get_target_channel_name(const struct lttng_action *action);

/*!
@brief
    Sets the target tracing domain of the “increment map value”
    trigger action \lt_p{action} to \lt_p{domain}.

The target domain selects which tracer owns the target
\ref api_map_channel "map channel": a given map channel name may
exist in more than one domain of the target recording session, so
the domain disambiguates the lookup LTTng performs when it executes
\lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to set the target
    domain.
@param[in] domain
    Target tracing domain of \lt_p{action}.

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    - \lt_p{domain} is #LTTNG_DOMAIN_KERNEL or #LTTNG_DOMAIN_UST.

@sa lttng_action_increment_map_value_get_target_domain() --
    Get the target tracing domain of an “increment map value”
    trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_set_target_domain(struct lttng_action *action,
						   enum lttng_domain_type domain);

/*!
@brief
    Sets \lt_p{*domain} to the target tracing domain of the
    “increment map value” trigger action \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to get the target
    domain.
@param[out] domain
    <strong>On success</strong>, this function sets \lt_p{*domain} to
    the target tracing domain of \lt_p{action}.

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_UNSET
    The target domain of \lt_p{action} is not set.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}
    @lt_pre_not_null{domain}

@sa lttng_action_increment_map_value_set_target_domain() --
    Set the target tracing domain of an “increment map value”
    trigger action.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_get_target_domain(const struct lttng_action *action,
						   enum lttng_domain_type *domain);

/*!
@brief
    Sets the \ref api_trigger_action_incr_map_val_key_template "key template"
    of the “increment map value” trigger action \lt_p{action} to
    a copy of \lt_p{key_template}.

When LTTng executes \lt_p{action}, it interpolates the placeholders of
the key template against the matching event of the containing
\ref api_trigger_cond_er_matches "“event rule matches” trigger condition"
to compute the <em>effective key</em>, then increments the map entry
which the target \ref api_map_channel "map channel" associates to that
key.

See \ref api_trigger_action_incr_map_val_key_template for details.

Build a key template with
lttng_key_template_create_from_string().

@param[in] action
    “Increment map value” trigger action of which to set the key
    template.
@param[in] key_template
    @parblock
    Key template to copy into \lt_p{action}.

    \lt_p{action} stores a deep copy of \lt_p{key_template}; the
    caller retains ownership of \lt_p{key_template} and may destroy
    it as soon as this function returns.
    @endparblock

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
    Build a key template by parsing a template string.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_increment_map_value_set_key_template(struct lttng_action *action,
						  const struct lttng_key_template *key_template);

/*!
@brief
    Returns the
    \ref api_trigger_action_incr_map_val_key_template "key template"
    of the “increment map value” trigger action \lt_p{action}.

@param[in] action
    “Increment map value” trigger action of which to get the key
    template.

@returns
    @parblock
    Key template of \lt_p{action}, or \c NULL if unset.

    \lt_p{action} owns the returned key template, which remains
    valid until the next setter call with \lt_p{action}.
    @endparblock

@pre
    @lt_pre_not_null{action}
    @lt_pre_has_type{action,LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE}

@sa lttng_action_increment_map_value_set_key_template() --
    Set the key template of an
    “increment map value” trigger action.
@sa lttng_key_template_to_string() --
    Render a key template back to its string form.
*/
LTTNG_EXPORT extern const struct lttng_key_template *
lttng_action_increment_map_value_get_key_template(const struct lttng_action *action);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_INCREMENT_MAP_VALUE_H */
