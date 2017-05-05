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

#ifndef LTTNG_EVALUATION_INTERNAL_H
#define LTTNG_EVALUATION_INTERNAL_H

#include <lttng/condition/evaluation.h>
#include <common/macros.h>
#include <common/buffer-view.h>
#include <stdbool.h>

typedef void (*evaluation_destroy_cb)(struct lttng_evaluation *evaluation);
typedef ssize_t (*evaluation_serialize_cb)(struct lttng_evaluation *evaluation,
		char *buf);

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
ssize_t lttng_evaluation_create_from_buffer(const struct lttng_buffer_view *view,
		struct lttng_evaluation **evaluation);

LTTNG_HIDDEN
ssize_t lttng_evaluation_serialize(struct lttng_evaluation *evaluation,
		char *buf);

#endif /* LTTNG_EVALUATION_INTERNAL_H */
