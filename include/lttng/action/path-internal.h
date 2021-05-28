/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_PATH_INTERNAL_H
#define LTTNG_ACTION_PATH_INTERNAL_H

#include <lttng/action/path.h>
#include <common/macros.h>
#include <common/dynamic-array.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_action_path {
	struct lttng_dynamic_array indexes;
};

/* Assumes that 'dst' is uninitialized. */
LTTNG_HIDDEN
int lttng_action_path_copy(const struct lttng_action_path *src,
		struct lttng_action_path *dst);

LTTNG_HIDDEN
ssize_t lttng_action_path_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_action_path **action_path);

LTTNG_HIDDEN
int lttng_action_path_serialize(const struct lttng_action_path *action_path,
		struct lttng_payload *payload);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_PATH_INTERNAL_H */
