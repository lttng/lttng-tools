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

struct lttng_action;
struct lttng_condition;
struct lttng_trigger;
/* A set of triggers. */
struct lttng_triggers;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_register_trigger_status {
	LTTNG_REGISTER_TRIGGER_STATUS_OK = 0,
	LTTNG_REGISTER_TRIGGER_STATUS_INVALID = -1,
};

enum lttng_trigger_status {
	LTTNG_TRIGGER_STATUS_OK = 0,
	LTTNG_TRIGGER_STATUS_ERROR = -1,
	LTTNG_TRIGGER_STATUS_UNKNOWN = -2,
	LTTNG_TRIGGER_STATUS_INVALID = -3,
	LTTNG_TRIGGER_STATUS_UNSET = -4,
	LTTNG_TRIGGER_STATUS_UNSUPPORTED = -5,
	LTTNG_TRIGGER_STATUS_PERMISSION_DENIED = -6,
};

/*
 * Create a trigger object associating a condition and an action.
 *
 * A trigger associates a condition and an action to take whenever the
 * condition evaluates to true. Such actions can, for example, consist
 * in the emission of a notification to clients listening through
 * notification channels.
 *
 * Prior to 2.13, the caller had to retain the ownership of both the condition
 * and action. Both objects had to be kept alive for the lifetime of the trigger
 * object. This is no longer the case as the condition and action objects are
 * internally reference counted. It is safe to destroy a condition and an action
 * after using them to create a trigger. However, they should no longer be used.
 *
 * If the action is a notification action with capture descriptors,
 * the condition must be an event rule condition.
 *
 * A trigger must be registered in order to become activate and can
 * be destroyed after its registration.
 *
 * Returns a trigger object on success, NULL on error.
 * Trigger objects must be destroyed using the lttng_trigger_destroy()
 * function.
 */
LTTNG_EXPORT extern struct lttng_trigger *lttng_trigger_create(struct lttng_condition *condition,
							       struct lttng_action *action);

/*
 * Set the user identity (uid) of a trigger.
 *
 * Only available for the root user (uid 0).
 *
 * Returns LTTNG_TRIGGER_STATUS_OK on success,
 * LTTNG_TRIGGER_STATUS_EPERM if not authorized,
 * LTTNG_TRIGGER_STATUS_INVALID if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_trigger_set_owner_uid(struct lttng_trigger *trigger, uid_t uid);

/*
 * Get the user identity (uid) of a trigger.
 *
 * Returns LTTNG_TRIGGER_STATUS_OK on success,
 * LTTNG_TRIGGER_STATUS_UNSET if unset,
 * LTTNG_TRIGGER_STATUS_INVALID if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_trigger_get_owner_uid(const struct lttng_trigger *trigger, uid_t *uid);

/*
 * Get the condition of a trigger.
 *
 * The caller acquires no ownership of the returned condition.
 *
 * Returns a condition on success, NULL on error.
 */
LTTNG_EXPORT extern struct lttng_condition *
lttng_trigger_get_condition(struct lttng_trigger *trigger);

LTTNG_EXPORT extern const struct lttng_condition *
lttng_trigger_get_const_condition(const struct lttng_trigger *trigger);

/*
 * Get the action of a trigger.
 *
 * The caller acquires no ownership of the returned action.
 *
 * Returns an action on success, NULL on error.
 */
LTTNG_EXPORT extern struct lttng_action *lttng_trigger_get_action(struct lttng_trigger *trigger);

LTTNG_EXPORT extern const struct lttng_action *
lttng_trigger_get_const_action(const struct lttng_trigger *trigger);

/*
 * Get the name of a trigger.
 *
 * The caller does not assume the ownership of the returned name.
 * The name shall only only be used for the duration of the trigger's
 * lifetime, or until a different name is set.
 *
 * Returns LTTNG_TRIGGER_STATUS_OK and a pointer to the trigger's name on
 * success, LTTNG_TRIGGER_STATUS_INVALID if an invalid parameter is passed,
 * or LTTNG_TRIGGER_STATUS_UNSET if the trigger is unnamed.
 */
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_trigger_get_name(const struct lttng_trigger *trigger, const char **name);

/*
 * Destroy (frees) a trigger object.
 */
LTTNG_EXPORT extern void lttng_trigger_destroy(struct lttng_trigger *trigger);

/*
 * Register a trigger to the session daemon with a given name.
 *
 * The trigger object can be destroyed after this call.
 * On success, this function will set the trigger's name to `name`.
 *
 * Returns an LTTng status code.
 */
LTTNG_EXPORT extern enum lttng_error_code
lttng_register_trigger_with_name(struct lttng_trigger *trigger, const char *name);

/*
 * Register a trigger to the session daemon, generating a unique name for its
 * owner.
 *
 * The trigger can be destroyed after this call.
 * On success, this function will set the trigger's name to the generated
 * name.
 *
 * Returns an LTTng status code.
 */
LTTNG_EXPORT extern enum lttng_error_code
lttng_register_trigger_with_automatic_name(struct lttng_trigger *trigger);

/*
 * Unregister a trigger from the session daemon.
 *
 * The trigger can be destroyed after this call.
 *
 * Return 0 on success, a negative LTTng error code on error.
 */
LTTNG_EXPORT extern int lttng_unregister_trigger(const struct lttng_trigger *trigger);

/*
 * List triggers for the current user.
 *
 * On success, a newly-allocated trigger set is returned.
 *
 * The trigger set must be destroyed by the caller (see
 * lttng_triggers_destroy()).
 *
 * Returns LTTNG_OK on success, else a suitable LTTng error code.
 */
LTTNG_EXPORT extern enum lttng_error_code lttng_list_triggers(struct lttng_triggers **triggers);

/*
 * Get a trigger from the set at a given index.
 *
 * Note that the trigger set maintains the ownership of the returned trigger.
 * It must not be destroyed by the user, nor should a reference to it be held
 * beyond the lifetime of the trigger set.
 *
 * Returns a trigger, or NULL on error.
 */
LTTNG_EXPORT extern const struct lttng_trigger *
lttng_triggers_get_at_index(const struct lttng_triggers *triggers, unsigned int index);

/*
 * Get the number of triggers in a trigger set.
 *
 * Return LTTNG_TRIGGER_STATUS_OK on success,
 * LTTNG_TRIGGER_STATUS_INVALID when invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_trigger_status
lttng_triggers_get_count(const struct lttng_triggers *triggers, unsigned int *count);

/*
 * Destroy a trigger set.
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

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_TRIGGER_H */
