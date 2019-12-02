/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_GROUP_H
#define LTTNG_ACTION_GROUP_H

struct lttng_action;
struct lttng_action_group;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated action group object.
 *
 * Returns a new action group on success, NULL on failure. This action group
 * must be destroyed using lttng_action_group_destroy().
 */
extern struct lttng_action *lttng_action_group_create(void);

/*
 * Add an action to an lttng_action object of type LTTNG_ACTION_GROUP.
 *
 * The action group acquires a reference to the action. The action can be
 * safely destroyed after calling this function. An action must not be
 * modified after adding it to a group.
 *
 * Adding an action group to an action group is not supported.
 */
extern enum lttng_action_status lttng_action_group_add_action(
		struct lttng_action *group, struct lttng_action *action);

/*
 * Get the number of actions in an action group.
 */
extern enum lttng_action_status lttng_action_group_get_count(
		const struct lttng_action *group, unsigned int *count);

/*
 * Get an action from the action group at a given index.
 *
 * Note that the group maintains the ownership of the returned action.
 * It must not be destroyed by the user, nor should it be held beyond
 * the lifetime of the action group.
 *
 * Returns an action, or NULL on error.
 */
extern const struct lttng_action *lttng_action_group_get_at_index(
		const struct lttng_action *group,
		unsigned int index);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_GROUP_H */
