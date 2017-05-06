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

#ifndef LTTNG_ACTION_INTERNAL_H
#define LTTNG_ACTION_INTERNAL_H

#include <lttng/action/action.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <stdbool.h>
#include <sys/types.h>

typedef bool (*action_validate_cb)(struct lttng_action *action);
typedef void (*action_destroy_cb)(struct lttng_action *action);
typedef ssize_t (*action_serialize_cb)(struct lttng_action *action, char *buf);

struct lttng_action {
	enum lttng_action_type type;
	action_validate_cb validate;
	action_serialize_cb serialize;
	action_destroy_cb destroy;
};

struct lttng_action_comm {
	/* enum lttng_action_type */
	int8_t action_type;
} LTTNG_PACKED;

LTTNG_HIDDEN
bool lttng_action_validate(struct lttng_action *action);

LTTNG_HIDDEN
ssize_t lttng_action_serialize(struct lttng_action *action, char *buf);

LTTNG_HIDDEN
ssize_t lttng_action_create_from_buffer(const struct lttng_buffer_view *view,
		struct lttng_action **action);

#endif /* LTTNG_ACTION_INTERNAL_H */
