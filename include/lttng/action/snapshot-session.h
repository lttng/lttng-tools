/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_SNAPSHOT_SESSION_H
#define LTTNG_ACTION_SNAPSHOT_SESSION_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_action;
struct lttng_snapshot_output;
struct lttng_rate_policy;

/*
 * Create a newly allocated snapshot-session action object.
 *
 * A snapshot session action object must have a session name set to be
 * considered valid when used with a trigger object (lttng_trigger). A name can
 * be set using `lttng_action_snapshot_session_set_session_name`.
 *
 * Returns a new action on success, NULL on failure. This action must be
 * destroyed using lttng_action_destroy().
 */
LTTNG_EXPORT extern struct lttng_action *lttng_action_snapshot_session_create(void);

/*
 * Set the session name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_SNAPSHOT_SESSION.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_set_session_name(struct lttng_action *action,
					       const char *session_name);

/*
 * Get the session name of an lttng_action object of type
 * LTTNG_ACTION_TYPE_SNAPSHOT_SESSION.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_get_session_name(const struct lttng_action *action,
					       const char **session_name);

/*
 * Set an explicit snapshot output for this snapshot session action.
 *
 * The given snapshot output will be used instead of the session's
 * default snapshot output.
 *
 * This function takes ownership of the given snapshot output.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_set_output(struct lttng_action *action,
					 struct lttng_snapshot_output *output);

/*
 * Get the explicit snapshot output for this snapshot session action.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_get_output(const struct lttng_action *action,
					 const struct lttng_snapshot_output **output);

/*
 * Set the rate policy of a snapshot session action.
 *
 * Returns LTTNG_ACTION_STATUS_OK on success,
 * LTTNG_ACTION_STATUS_ERROR on internal error,
 * LTTNG_ACTION_STATUS_INVALID if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_set_rate_policy(struct lttng_action *action,
					      const struct lttng_rate_policy *policy);

/*
 * Get the rate policy of a snapshot session action.
 *
 * Returns LTTNG_ACTION_STATUS_OK on success,
 * LTTNG_ACTION_STATUS_INVALID if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_snapshot_session_get_rate_policy(const struct lttng_action *action,
					      const struct lttng_rate_policy **policy);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_SNAPSHOT_SESSION_H */
