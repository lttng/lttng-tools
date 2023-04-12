/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_PATH_H
#define LTTNG_ACTION_PATH_H

#include <lttng/lttng-export.h>

#include <stddef.h>
#include <stdint.h>

struct lttng_action_path;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_action_path_status {
	LTTNG_ACTION_PATH_STATUS_OK = 0,
	LTTNG_ACTION_PATH_STATUS_INVALID = -1,
};

/*
 * Create a path to an action.
 *
 * An action path indicates how to reach a given action from the action
 * of a trigger. The action of a trigger is implicitly the root of an action
 * path.
 *
 * The indexes of an action path allow the resolution of an action.
 * The indexes that make-up an action path indicate the index of the successive
 * action lists that must be traversed to reach the target action.
 *
 * For instance, an action path that has a single index 'N' implies that:
 *   - The root action is a list,
 *   - The target action is the 'N'-th action in that list.
 *
 * An action path with two indexes, N1 and N2 implies that:
 *   - The root action is an action list (L1),
 *   - The N1-th action of the action list (L1) is also a list (L2),
 *   - The target action is the N2-th action of the L2 list.
 *
 * The `indexes` are copied internally and can be disposed-of by the caller.
 */
LTTNG_EXPORT extern struct lttng_action_path *lttng_action_path_create(const uint64_t *indexes,
								       size_t index_count);

/*
 * Get the count of indexes in an action path.
 */
LTTNG_EXPORT extern enum lttng_action_path_status
lttng_action_path_get_index_count(const struct lttng_action_path *path, size_t *index_count);

/*
 * Get an index from an action path.
 */
LTTNG_EXPORT extern enum lttng_action_path_status lttng_action_path_get_index_at_index(
	const struct lttng_action_path *path, size_t path_index, uint64_t *out_index);

/*
 * Destroy an action path object.
 */
LTTNG_EXPORT extern void lttng_action_path_destroy(struct lttng_action_path *action_path);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_PATH_H */
