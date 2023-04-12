/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_LIST_INTERNAL_H
#define LTTNG_ACTION_LIST_INTERNAL_H

#include <common/macros.hpp>

#include <sys/types.h>

struct lttng_action;
struct lttng_payload_view;
struct mi_writer;
struct mi_lttng_error_query_callbacks;
struct lttng_dynamic_array;
struct lttng_trigger;

/*
 * Create an action list from a payload view.
 *
 * On success, return the number of bytes consumed from `view`, and the created
 * list in `*list`. On failure, return -1.
 */
extern ssize_t lttng_action_list_create_from_payload(struct lttng_payload_view *view,
						     struct lttng_action **list);

extern struct lttng_action *
lttng_action_list_borrow_mutable_at_index(const struct lttng_action *list, unsigned int index);

enum lttng_error_code
lttng_action_list_mi_serialize(const struct lttng_trigger *trigger,
			       const struct lttng_action *action,
			       struct mi_writer *writer,
			       const struct mi_lttng_error_query_callbacks *error_query_callbacks,
			       struct lttng_dynamic_array *action_path_indexes);

#endif /* LTTNG_ACTION_LIST_INTERNAL_H */
