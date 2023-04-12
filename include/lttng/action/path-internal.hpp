/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_PATH_INTERNAL_H
#define LTTNG_ACTION_PATH_INTERNAL_H

#include <common/dynamic-array.hpp>
#include <common/macros.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/action/path.h>

#include <sys/types.h>

struct lttng_action_path {
	struct lttng_dynamic_array indexes;
};

int lttng_action_path_copy(const struct lttng_action_path *src, struct lttng_action_path **dst);

ssize_t lttng_action_path_create_from_payload(struct lttng_payload_view *view,
					      struct lttng_action_path **action_path);

int lttng_action_path_serialize(const struct lttng_action_path *action_path,
				struct lttng_payload *payload);

#endif /* LTTNG_ACTION_PATH_INTERNAL_H */
