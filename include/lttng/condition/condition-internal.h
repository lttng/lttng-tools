/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_CONDITION_INTERNAL_H
#define LTTNG_CONDITION_INTERNAL_H

#include <lttng/condition/condition.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <stdbool.h>
#include <urcu/list.h>
#include <stdint.h>

typedef void (*condition_destroy_cb)(struct lttng_condition *condition);
typedef bool (*condition_validate_cb)(const struct lttng_condition *condition);
typedef ssize_t (*condition_serialize_cb)(
		const struct lttng_condition *condition, char *buf);
typedef bool (*condition_equal_cb)(const struct lttng_condition *a,
		const struct lttng_condition *b);
typedef ssize_t (*condition_create_from_buffer_cb)(
		const struct lttng_buffer_view *view,
		struct lttng_condition **condition);

struct lttng_condition {
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
void lttng_condition_init(struct lttng_condition *condition,
		enum lttng_condition_type type);

LTTNG_HIDDEN
bool lttng_condition_validate(const struct lttng_condition *condition);

LTTNG_HIDDEN
ssize_t lttng_condition_create_from_buffer(
		const struct lttng_buffer_view *buffer,
		struct lttng_condition **condition);

LTTNG_HIDDEN
ssize_t lttng_condition_serialize(const struct lttng_condition *condition,
		char *buf);

LTTNG_HIDDEN
bool lttng_condition_is_equal(const struct lttng_condition *a,
		const struct lttng_condition *b);

#endif /* LTTNG_CONDITION_INTERNAL_H */
