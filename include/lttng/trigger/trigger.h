/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRIGGER_H
#define LTTNG_TRIGGER_H

#include <lttng/constant.h>
#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger
@{
*/

struct lttng_action;
struct lttng_condition;

/*!
@struct lttng_trigger

@brief
    Trigger (opaque type).
*/
struct lttng_trigger;

/*!
@struct lttng_triggers

@brief
    Trigger list (opaque type).
*/
struct lttng_triggers;

enum lttng_register_trigger_status {
	LTTNG_REGISTER_TRIGGER_STATUS_OK = 0,
	LTTNG_REGISTER_TRIGGER_STATUS_INVALID = -1,
};

/*!
@brief
    Return type of trigger API functions.
*/
enum lttng_trigger_status {
	/// Success.
	LTTNG_TRIGGER_STATUS_OK = 0,

	/// Error.
	LTTNG_TRIGGER_STATUS_ERROR = -1,

	/* Unused for the moment */
	LTTNG_TRIGGER_STATUS_UNKNOWN = -2,
	LTTNG_TRIGGER_STATUS_UNSUPPORTED = -5,

	/// Unsatisfied precondition.
	LTTNG_TRIGGER_STATUS_INVALID = -3,

	/// Not set.
	LTTNG_TRIGGER_STATUS_UNSET = -4,

	/// Permission denied.
	LTTNG_TRIGGER_STATUS_PERMISSION_DENIED = -6,
};

/*!
@brief
    Creates a trigger to attempt to execute the
    \ref api_trigger_action "action" \lt_p{action}
    when the \ref api_trigger_cond "condition" \lt_p{condition}
    is satisfied.

This function only creates the trigger object, but doesn't register it
to the LTTng session daemon: use
lttng_register_trigger_with_automatic_name() or
lttng_register_trigger_with_name().

@param[in] condition
    Condition of the trigger to create (not moved).
@param[in] action
    @parblock
    Action of the trigger to create (not moved).

    If you need LTTng to execute more than one action when
    \lt_p{condition} is satisfied, then use an
    \ref api_trigger_action_list "action list".
    @endparblock

@returns
    @parblock
    Trigger on success, or \c NULL on error.

    Destroy the returned trigger with lttng_trigger_destroy().
    @endparblock

@pre
    @lt_pre_not_null{condition}
    @lt_pre_not_null{action}
*/
LTTNG_EXPORT extern struct lttng_trigger *lttng_trigger_create(struct lttng_condition *condition,
							       struct lttng_action *action);

/*!
@brief
    Sets the owner Unix user ID (UID) of the trigger \lt_p{trigger} to
    \lt_p{uid}.

This function can only succeed if your Unix user is \c root and you're
\ref api-gen-sessiond-conn "connecting" to a root LTTng session daemon.

When you register \lt_p{trigger} with lttng_register_trigger_with_name()
or lttng_register_trigger_with_automatic_name() after calling this
function, it's equivalent to some process of Unix user \lt_p{uid}, part
of the tracing group, doing it.

@param[in] trigger
    Trigger of which to set the owner UID to \lt_p{uid}.
@param[in] uid
    Owner UID of \lt_p{trigger}.

@retval #LTTNG_TRIGGER_STATUS_OK
    Success.
@retval #LTTNG_TRIGGER_STATUS_PERMISSION_DENIED
    Permission denied.
@retval #LTTNG_TRIGGER_STATUS_INVALID
    Unsatisfied precondition.

@pre
    - Your Unix user is <code>root</code> (UID&nbsp;0).
    @lt_pre_not_null{trigger}
    - \lt_p{trigger} isn't registered yet (you didn't call
      lttng_register_trigger_with_name() or
      lttng_register_trigger_with_automatic_name() with it).

@sa lttng_trigger_get_owner_uid() --
    Get the owner UID of a trigger.
*/
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_trigger_set_owner_uid(struct lttng_trigger *trigger, uid_t uid);

/*!
@brief
    Sets \lt_p{*uid} to the owner Unix user ID (UID) of the trigger
    \lt_p{trigger}.

@param[in] trigger
    Trigger of which to get the owner UID.
@param[out] uid
    <strong>On success</strong>, this function sets \lt_p{*uid}
    to the owner UID of \lt_p{trigger}.

@retval #LTTNG_TRIGGER_STATUS_OK
    Success.
@retval #LTTNG_TRIGGER_STATUS_UNSET
    \lt_p{trigger} has no specific owner UID.
@retval #LTTNG_TRIGGER_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{trigger}
    @lt_pre_not_null{uid}

@sa lttng_trigger_set_owner_uid() --
    Set the owner UID of a trigger.
*/
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_trigger_get_owner_uid(const struct lttng_trigger *trigger, uid_t *uid);

/*!
@brief
    Returns the \ref api_trigger_cond "condition" of the
    trigger \lt_p{trigger}.

@param[in] trigger
    Trigger of which to get the condition.

@returns
    @parblock
    Condition of \lt_p{trigger}, or \c NULL on error.

    \lt_p{trigger} owns the returned condition.

    The returned condition remains valid as long
    as \lt_p{trigger} exists.
    @endparblock

@pre
    @lt_pre_not_null{trigger}
*/
LTTNG_EXPORT extern struct lttng_condition *
lttng_trigger_get_condition(struct lttng_trigger *trigger);

/*!
@brief
    Returns the \ref api_trigger_cond "condition" of the
    trigger \lt_p{trigger} (<code>const</code> version).

@param[in] trigger
    Trigger of which to get the condition.

@returns
    @parblock
    Condition of \lt_p{trigger}, or \c NULL on error.

    \lt_p{trigger} owns the returned condition.

    The returned condition remains valid as long
    as \lt_p{trigger} exists.
    @endparblock

@pre
    @lt_pre_not_null{trigger}
*/
LTTNG_EXPORT extern const struct lttng_condition *
lttng_trigger_get_const_condition(const struct lttng_trigger *trigger);

/*!
@brief
    Returns the \ref api_trigger_action "action" of the
    trigger \lt_p{trigger}.

@param[in] trigger
    Trigger of which to get the action.

@returns
    @parblock
    Action of \lt_p{trigger}, or \c NULL on error.

    \lt_p{trigger} owns the returned action.

    The returned action remains valid as long
    as \lt_p{trigger} exists.
    @endparblock

@pre
    @lt_pre_not_null{trigger}
*/
LTTNG_EXPORT extern struct lttng_action *lttng_trigger_get_action(struct lttng_trigger *trigger);

/*!
@brief
    Returns the \ref api_trigger_action "action" of the
    trigger \lt_p{trigger} (<code>const</code> version).

@param[in] trigger
    Trigger of which to get the action.

@returns
    @parblock
    Action of \lt_p{trigger}, or \c NULL on error.

    \lt_p{trigger} owns the returned action.

    The returned action remains valid as long
    as \lt_p{trigger} exists.
    @endparblock

@pre
    @lt_pre_not_null{trigger}
*/
LTTNG_EXPORT extern const struct lttng_action *
lttng_trigger_get_const_action(const struct lttng_trigger *trigger);

/*!
@brief
    Sets \lt_p{*name} to the name of the trigger \lt_p{trigger}.

@param[in] trigger
    Trigger of which to get the name.
@param[out] name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*name}
    to the name of \lt_p{trigger}.

    \lt_p{trigger} owns \lt_p{*name}.

    \lt_p{*name} remains valid until the next
    function call with \lt_p{trigger}.
    @endparblock

@retval #LTTNG_TRIGGER_STATUS_OK
    Success.
@retval #LTTNG_TRIGGER_STATUS_UNSET
    \lt_p{trigger} has no name.
@retval #LTTNG_TRIGGER_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{trigger}
    @lt_pre_not_null{name}
*/
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_trigger_get_name(const struct lttng_trigger *trigger, const char **name);

/*!
@brief
    Destroys the trigger \lt_p{trigger}.

@param[in] trigger
    @parblock
    Trigger to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_trigger_destroy(struct lttng_trigger *trigger);

/*!
@brief
    Registers the trigger \lt_p{trigger} to the session daemon
    with the name \lt_p{name}.

This function
\ref api-gen-sessiond-conn "connects to the session daemon" to
register \lt_p{trigger}.

If lttng_trigger_get_owner_uid() returns #LTTNG_TRIGGER_STATUS_UNSET
with \lt_p{trigger}, then this function sets your current UID as the
owner UID for \lt_p{trigger}.

@param[in] trigger
    @parblock
    Trigger to register to the session daemon (not moved).

    It's safe to destroy \lt_p{trigger} with lttng_trigger_destroy()
    after calling this function.
    @endparblock
@param[in] name
    Name of the trigger to register (copied).

@returns
    <dl>
      <dt>#LTTNG_OK
      <dd>Success

      <dt>Another #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{trigger}
    - You created \lt_p{trigger} with lttng_trigger_create().
    - The condition and action of \lt_p{trigger} are valid.
      The documentation of each trigger condition and action creation
      function indicates how to build a valid condition/action.
    - Your Unix user ID (UID) is either 0 (<code>root</code>) or
      the same as the
      \link lttng_trigger_get_owner_uid() owner UID\endlink of
      \lt_p{trigger}.
    @lt_pre_not_null{name}
    - No other trigger with the same
      \link lttng_trigger_get_owner_uid() owner UID\endlink
      has the name \lt_p{name}.

@sa lttng_register_trigger_with_automatic_name() --
    Register a trigger with a generated unique name.
@sa lttng_unregister_trigger() --
    Unregister a trigger.
*/
LTTNG_EXPORT extern enum lttng_error_code
lttng_register_trigger_with_name(struct lttng_trigger *trigger, const char *name);

/*!
@brief
    Registers the trigger \lt_p{trigger} to the session daemon
    with a generated unique name.

This function
\ref api-gen-sessiond-conn "connects to the session daemon" to
register \lt_p{trigger}.

If lttng_trigger_get_owner_uid() returns #LTTNG_TRIGGER_STATUS_UNSET
with \lt_p{trigger}, then this function sets your current UID as the
owner UID for \lt_p{trigger}.

@param[in] trigger
    @parblock
    Trigger to register to the session daemon (not moved).

    It's safe to destroy \lt_p{trigger} with lttng_trigger_destroy()
    after calling this function.
    @endparblock

@returns
    <dl>
      <dt>#LTTNG_OK
      <dd>Success

      <dt>Another #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{trigger}
    - You created \lt_p{trigger} with lttng_trigger_create().
    - The condition and action of \lt_p{trigger} are valid.
      The documentation of each trigger condition and action creation
      function indicates how to build a valid condition/action.
    - Your Unix user ID (UID) is either 0 (<code>root</code>) or
      the same as the
      \link lttng_trigger_get_owner_uid() owner UID\endlink of
      \lt_p{trigger}.

@sa lttng_register_trigger_with_name() --
    Register a trigger with a specific name.
@sa lttng_unregister_trigger() --
    Unregister a trigger.
*/
LTTNG_EXPORT extern enum lttng_error_code
lttng_register_trigger_with_automatic_name(struct lttng_trigger *trigger);

/*!
@brief
    Unregisters the trigger \lt_p{trigger} from the session daemon.

This function
\ref api-gen-sessiond-conn "connects to the session daemon" to
unregister \lt_p{trigger}.

@param[in] trigger
    @parblock
    Trigger to unregister from the session daemon (not moved).

    It's safe to destroy \lt_p{trigger} with lttng_trigger_destroy()
    after calling this function.
    @endparblock

@returns
    <dl>
      <dt>0
      <dd>Success

      <dt>\em Negative #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{trigger}
    - \lt_p{trigger} is currently registered to the session daemon
      to connect to.
    - Your Unix user ID (UID) is either 0 (<code>root</code>) or
      the same as the
      \link lttng_trigger_get_owner_uid() owner UID\endlink of
      \lt_p{trigger}.

@sa lttng_register_trigger_with_automatic_name() --
    Register a trigger with a generated unique name.
@sa lttng_register_trigger_with_name() --
    Register a trigger with a specific name.
*/
LTTNG_EXPORT extern int lttng_unregister_trigger(const struct lttng_trigger *trigger);

/*!
@brief
    Sets \lt_p{*triggers} to a list of available triggers.

This function
\ref api-gen-sessiond-conn "connects to the session daemon" to
list triggers.

The available triggers are, depending on your
Unix user ID (UID):

<dl>
  <dt>0 (<code>root</code>)
  <dd>All the triggers of the session daemon to connect to.

  <dt>Other UID \lt_var{UID}
  <dd>Only the triggers having the owner UID \lt_var{UID}.
</dl>

@param[out] triggers
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*triggers}
    to a list of available triggers.

    Destroy the returned trigger list with lttng_triggers_destroy().
    @endparblock

@returns
    <dl>
      <dt>#LTTNG_OK
      <dd>Success

      <dt>Another #lttng_error_code enumerator
      <dd>Error
    </dl>

@pre
    @lt_pre_conn
    @lt_pre_not_null{triggers}

@sa lttng_triggers_get_count() --
    Get the length of a trigger list.
@sa lttng_triggers_get_at_index() --
    Get a trigger from a trigger list by index.
*/
LTTNG_EXPORT extern enum lttng_error_code lttng_list_triggers(struct lttng_triggers **triggers);

/*!
@brief
    Returns the trigger of the trigger list \lt_p{triggers}
    at the index \lt_p{index}.

@param[in] triggers
    Trigger list of which to get the trigger
    at the index \lt_p{index}.
@param[in] index
    Index of the trigger to get from \lt_p{triggers}.

@returns
    @parblock
    Trigger of the triggers
    \lt_p{triggers} at the index \lt_p{index}, or \c NULL on error.

    \lt_p{triggers} owns the returned trigger.

    The returned trigger remains valid as long
    as \lt_p{triggers} exists.
    @endparblock

@pre
    @lt_pre_not_null{triggers}
    - \lt_p{index} is less than the number of triggers
      (as returned by lttng_triggers_get_count())
      of \lt_p{triggers}.

@sa lttng_triggers_get_count() --
    Get the length of a trigger list.
*/
LTTNG_EXPORT extern const struct lttng_trigger *
lttng_triggers_get_at_index(const struct lttng_triggers *triggers, unsigned int index);

/*!
@brief
    Sets \lt_p{*count} to the number of triggers contained in
    the trigger list \lt_p{triggers}.

@param[in] triggers
    Trigger list of which to get the number of contained triggers.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count}
    to the number of triggers in \lt_p{triggers}.

@retval #LTTNG_TRIGGER_STATUS_OK
    Success.
@retval #LTTNG_TRIGGER_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{triggers}
    @lt_pre_not_null{count}

@sa lttng_triggers_get_at_index() --
    Get a trigger from a trigger list by index.
*/
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_triggers_get_count(const struct lttng_triggers *triggers, unsigned int *count);

/*!
@brief
    Destroys the trigger list \lt_p{triggers}.

@param[in] triggers
    @parblock
    Trigger list to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_triggers_destroy(struct lttng_triggers *triggers);

/*
 * Deprecated: invocations should be replaced by
 * lttng_register_trigger_with_automatic_name().
 *
 * Register a trigger to the session daemon.
 *
 * The trigger can be destroyed after this call.
 *
 * Return 0 on success, a negative LTTng error code on error.
 */
LTTNG_DEPRECATED("Use lttng_register_trigger_with_automatic_name")
LTTNG_EXPORT extern int lttng_register_trigger(struct lttng_trigger *trigger);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_TRIGGER_H */
