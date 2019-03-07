/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVALUATION_INTERNAL_H
#define LTTNG_EVALUATION_INTERNAL_H

#include <lttng/condition/evaluation.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <common/dynamic-buffer.h>
#include <stdbool.h>
#include <sys/types.h>

typedef void (*evaluation_destroy_cb)(struct lttng_evaluation *evaluation);
typedef int (*evaluation_serialize_cb)(
		const struct lttng_evaluation *evaluation,
		struct lttng_dynamic_buffer *buf);

struct lttng_evaluation_comm {
	/* enum lttng_condition_type type */
	int8_t type;
	char payload[];
} LTTNG_PACKED;

struct lttng_evaluation {
	enum lttng_condition_type type;
	evaluation_serialize_cb serialize;
	evaluation_destroy_cb destroy;
};

LTTNG_HIDDEN
void lttng_evaluation_init(struct lttng_evaluation *evaluation,
		enum lttng_condition_type type);

LTTNG_HIDDEN
ssize_t lttng_evaluation_create_from_buffer(const struct lttng_buffer_view *view,
		struct lttng_evaluation **evaluation);

LTTNG_HIDDEN
int lttng_evaluation_serialize(const struct lttng_evaluation *evaluation,
		struct lttng_dynamic_buffer *buf);

#endif /* LTTNG_EVALUATION_INTERNAL_H */
