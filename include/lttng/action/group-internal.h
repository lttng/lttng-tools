/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_GROUP_INTERNAL_H
#define LTTNG_ACTION_GROUP_INTERNAL_H

#include <sys/types.h>

#include <common/macros.h>

struct lttng_action;
struct lttng_payload_view;

/*
 * Create an action group from a payload view.
 *
 * On success, return the number of bytes consumed from `view`, and the created
 * group in `*group`. On failure, return -1.
 */
LTTNG_HIDDEN
extern ssize_t lttng_action_group_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action **group);

LTTNG_HIDDEN
extern struct lttng_action *lttng_action_group_borrow_mutable_at_index(
		const struct lttng_action *group, unsigned int index);

#endif /* LTTNG_ACTION_GROUP_INTERNAL_H */
