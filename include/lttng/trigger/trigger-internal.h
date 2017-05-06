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

#ifndef LTTNG_TRIGGER_INTERNAL_H
#define LTTNG_TRIGGER_INTERNAL_H

#include <lttng/trigger/trigger.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

struct lttng_trigger {
	struct lttng_condition *condition;
	struct lttng_action *action;
};

struct lttng_trigger_comm {
	/* length excludes its own length. */
	uint32_t length;
	/* A condition and action object follow. */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_trigger_create_from_buffer(const struct lttng_buffer_view *view,
		struct lttng_trigger **trigger);

LTTNG_HIDDEN
ssize_t lttng_trigger_serialize(struct lttng_trigger *trigger, char *buf);

LTTNG_HIDDEN
bool lttng_trigger_validate(struct lttng_trigger *trigger);

#endif /* LTTNG_TRIGGER_INTERNAL_H */
