/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_INTERNAL_H
#define LTTNG_CONDITION_INTERNAL_H

#include <lttng/condition/condition.h>
#include <common/macros.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <stdbool.h>
#include <urcu/list.h>
#include <urcu/ref.h>
#include <stdint.h>
#include <sys/types.h>

typedef void (*condition_destroy_cb)(struct lttng_condition *condition);
typedef bool (*condition_validate_cb)(const struct lttng_condition *condition);
typedef int (*condition_serialize_cb)(
		const struct lttng_condition *condition,
		struct lttng_payload *payload);
typedef bool (*condition_equal_cb)(const struct lttng_condition *a,
		const struct lttng_condition *b);
typedef ssize_t (*condition_create_from_payload_cb)(
		struct lttng_payload_view *view,
		struct lttng_condition **condition);

struct lttng_condition {
	/* Reference counting is only exposed to internal users. */
	struct urcu_ref ref;
	enum lttng_condition_type type;
	condition_validate_cb validate;
	condition_serialize_cb serialize;
	condition_equal_cb equal;
	condition_destroy_cb destroy;
};

struct lttng_condition_comm {
	/* enum lttng_condition_type */
	int8_t condition_type;
	char payload[];
};

LTTNG_HIDDEN
void lttng_condition_get(struct lttng_condition *condition);

LTTNG_HIDDEN
void lttng_condition_put(struct lttng_condition *condition);

LTTNG_HIDDEN
void lttng_condition_init(struct lttng_condition *condition,
		enum lttng_condition_type type);

LTTNG_HIDDEN
bool lttng_condition_validate(const struct lttng_condition *condition);

LTTNG_HIDDEN
ssize_t lttng_condition_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **condition);

LTTNG_HIDDEN
int lttng_condition_serialize(const struct lttng_condition *condition,
		struct lttng_payload *payload);

LTTNG_HIDDEN
bool lttng_condition_is_equal(const struct lttng_condition *a,
		const struct lttng_condition *b);

LTTNG_HIDDEN
const char *lttng_condition_type_str(enum lttng_condition_type type);

#endif /* LTTNG_CONDITION_INTERNAL_H */
