/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_INTERNAL_H
#define LTTNG_CONDITION_INTERNAL_H

#include <common/macros.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/condition/condition.h>
#include <lttng/lttng-error.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <urcu/list.h>
#include <urcu/ref.h>

struct mi_writer;
struct mi_lttng_error_query_callbacks;
struct lttng_trigger;

using condition_destroy_cb = void (*)(struct lttng_condition *);
using condition_validate_cb = bool (*)(const struct lttng_condition *);
using condition_serialize_cb = int (*)(const struct lttng_condition *, struct lttng_payload *);
using condition_equal_cb = bool (*)(const struct lttng_condition *, const struct lttng_condition *);
using condition_create_from_payload_cb = ssize_t (*)(struct lttng_payload_view *,
						     struct lttng_condition **);
using condition_mi_serialize_cb = enum lttng_error_code (*)(const struct lttng_condition *,
							    struct mi_writer *);

struct lttng_condition {
	/* Reference counting is only exposed to internal users. */
	struct urcu_ref ref;
	enum lttng_condition_type type;
	condition_validate_cb validate;
	condition_serialize_cb serialize;
	condition_equal_cb equal;
	condition_destroy_cb destroy;
	condition_mi_serialize_cb mi_serialize;
};

struct lttng_condition_comm {
	/* enum lttng_condition_type */
	int8_t condition_type;
	char payload[];
};

void lttng_condition_get(struct lttng_condition *condition);

void lttng_condition_put(struct lttng_condition *condition);

void lttng_condition_init(struct lttng_condition *condition, enum lttng_condition_type type);

bool lttng_condition_validate(const struct lttng_condition *condition);

ssize_t lttng_condition_create_from_payload(struct lttng_payload_view *view,
					    struct lttng_condition **condition);

int lttng_condition_serialize(const struct lttng_condition *condition,
			      struct lttng_payload *payload);

bool lttng_condition_is_equal(const struct lttng_condition *a, const struct lttng_condition *b);

enum lttng_error_code
lttng_condition_mi_serialize(const struct lttng_trigger *trigger,
			     const struct lttng_condition *condition,
			     struct mi_writer *writer,
			     const struct mi_lttng_error_query_callbacks *error_query_callbacks);

const char *lttng_condition_type_str(enum lttng_condition_type type);

#endif /* LTTNG_CONDITION_INTERNAL_H */
