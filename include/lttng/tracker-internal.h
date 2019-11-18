/*
 * Copyright (C) 2019 - Jonathan Rajotte-Julien <jonathan.rajotte-julien@efficios.com>
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

#ifndef LTTNG_TRACKER_INTERNAL_H
#define LTTNG_TRACKER_INTERNAL_H

#include <lttng/constant.h>
#include <common/macros.h>
#include <lttng/tracker.h>
#include <stdbool.h>

struct lttng_tracker_id {
	enum lttng_tracker_id_type type;
	int value;
	char *string;
};

LTTNG_HIDDEN
bool lttng_tracker_id_is_equal(const struct lttng_tracker_id *left,
		const struct lttng_tracker_id *right);

LTTNG_HIDDEN
struct lttng_tracker_id *lttng_tracker_id_copy(
		const struct lttng_tracker_id *orig);

#endif /* LTTNG_TRACKER_INTERNAL_H */
