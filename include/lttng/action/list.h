/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_LIST_H
#define LTTNG_ACTION_LIST_H

#include <lttng/lttng-export.h>

struct lttng_action;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated action list object.
 *
 * Returns a new action list on success, NULL on failure. This action list
 * must be destroyed using lttng_action_destroy().
 */
LTTNG_EXPORT extern struct lttng_action *lttng_action_list_create(void);

/*
 * Add an action to an lttng_action object of type LTTNG_ACTION_LIST.
 *
 * The action list acquires a reference to the action. The action can be
 * safely destroyed after calling this function. An action must not be
 * modified after adding it to a list.
 *
 * Adding an action list to an action list is not supported.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_list_add_action(struct lttng_action *list, struct lttng_action *action);

/*
 * Get the number of actions in an action list.
 */
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_list_get_count(const struct lttng_action *list, unsigned int *count);

/*
 * Get an action from the action list at a given index.
 *
 * Note that the list maintains the ownership of the returned action.
 * It must not be destroyed by the user, nor should it be held beyond
 * the lifetime of the action list.
 *
 * Returns an action, or NULL on error.
 */
LTTNG_EXPORT extern const struct lttng_action *
lttng_action_list_get_at_index(const struct lttng_action *list, unsigned int index);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_LIST_H */
