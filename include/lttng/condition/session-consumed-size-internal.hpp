/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_SESSION_CONSUMED_SIZE_INTERNAL_H
#define LTTNG_CONDITION_SESSION_CONSUMED_SIZE_INTERNAL_H

#include <common/buffer-view.hpp>
#include <common/macros.hpp>

#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/evaluation-internal.hpp>
#include <lttng/condition/session-consumed-size.h>

struct lttng_payload;
struct lttng_payload_view;

struct lttng_condition_session_consumed_size {
	struct lttng_condition parent;
	struct {
		bool set;
		uint64_t value;
	} consumed_threshold_bytes;
	char *session_name;
};

struct lttng_condition_session_consumed_size_comm {
	uint64_t consumed_threshold_bytes;
	/* Length includes the trailing \0. */
	uint32_t session_name_len;
	char session_name[];
} LTTNG_PACKED;

struct lttng_evaluation_session_consumed_size {
	struct lttng_evaluation parent;
	uint64_t session_consumed;
};

struct lttng_evaluation_session_consumed_size_comm {
	uint64_t session_consumed;
} LTTNG_PACKED;

struct lttng_evaluation *lttng_evaluation_session_consumed_size_create(uint64_t consumed);

ssize_t
lttng_condition_session_consumed_size_create_from_payload(struct lttng_payload_view *view,
							  struct lttng_condition **condition);

ssize_t
lttng_evaluation_session_consumed_size_create_from_payload(struct lttng_payload_view *view,
							   struct lttng_evaluation **evaluation);

#endif /* LTTNG_CONDITION_SESSION_CONSUMED_SIZE_INTERNAL_H */
