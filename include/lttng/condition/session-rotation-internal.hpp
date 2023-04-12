/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_SESSION_ROTATION_INTERNAL_H
#define LTTNG_CONDITION_SESSION_ROTATION_INTERNAL_H

#include "common/buffer-view.hpp"

#include <common/macros.hpp>

#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/evaluation-internal.hpp>
#include <lttng/condition/session-rotation.h>
#include <lttng/location.h>

struct lttng_condition_session_rotation {
	struct lttng_condition parent;
	char *session_name;
};

struct lttng_condition_session_rotation_comm {
	/* Length includes the trailing \0. */
	uint32_t session_name_len;
	char session_name[];
} LTTNG_PACKED;

struct lttng_evaluation_session_rotation {
	struct lttng_evaluation parent;
	uint64_t id;
	struct lttng_trace_archive_location *location;
};

struct lttng_evaluation_session_rotation_comm {
	uint64_t id;
	uint8_t has_location;
} LTTNG_PACKED;

ssize_t
lttng_condition_session_rotation_ongoing_create_from_payload(struct lttng_payload_view *view,
							     struct lttng_condition **condition);

ssize_t
lttng_condition_session_rotation_completed_create_from_payload(struct lttng_payload_view *view,
							       struct lttng_condition **condition);

struct lttng_evaluation *lttng_evaluation_session_rotation_ongoing_create(uint64_t id);

/* Ownership of location is transferred to the evaluation. */
struct lttng_evaluation *
lttng_evaluation_session_rotation_completed_create(uint64_t id,
						   struct lttng_trace_archive_location *location);

ssize_t
lttng_evaluation_session_rotation_ongoing_create_from_payload(struct lttng_payload_view *view,
							      struct lttng_evaluation **evaluation);

ssize_t lttng_evaluation_session_rotation_completed_create_from_payload(
	struct lttng_payload_view *view, struct lttng_evaluation **evaluation);

#endif /* LTTNG_CONDITION_SESSION_ROTATION_INTERNAL_H */
