/*
 * Copyright (C) 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_START_SESSION_INTERNAL_H
#define LTTNG_ACTION_START_SESSION_INTERNAL_H

#include <common/macros.hpp>

struct lttng_action;
struct lttng_payload_view;

/*
 * Create a "start session" action from a payload view.
 *
 * On success, return the number of bytes consumed from `view`, and the created
 * action in `*action`. On failure, return -1.
 */
extern ssize_t lttng_action_start_session_create_from_payload(struct lttng_payload_view *view,
							      struct lttng_action **action);

#endif /* LTTNG_ACTION_START_SESSION_INTERNAL_H */
