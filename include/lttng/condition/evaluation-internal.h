/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVALUATION_INTERNAL_H
#define LTTNG_EVALUATION_INTERNAL_H

#include <lttng/condition/evaluation.h>
#include <lttng/condition/condition.h>
#include <common/macros.h>
#include <stdbool.h>
#include <sys/types.h>

struct lttng_payload;
struct lttng_payload_view;

typedef void (*evaluation_destroy_cb)(struct lttng_evaluation *evaluation);
typedef int (*evaluation_serialize_cb)(
		const struct lttng_evaluation *evaluation,
		struct lttng_payload *payload);

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
ssize_t lttng_evaluation_create_from_payload(
		const struct lttng_condition *condition,
		struct lttng_payload_view *view,
		struct lttng_evaluation **evaluation);

LTTNG_HIDDEN
int lttng_evaluation_serialize(const struct lttng_evaluation *evaluation,
		struct lttng_payload *payload);

#endif /* LTTNG_EVALUATION_INTERNAL_H */
