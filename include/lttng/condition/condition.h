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

#ifndef LTTNG_CONDITION_H
#define LTTNG_CONDITION_H

#include <lttng/lttng.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_condition;

enum lttng_condition_type {
	LTTNG_CONDITION_TYPE_UNKNOWN = -1,
	LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW = 102,
	LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH = 101,
};

enum lttng_condition_status {
	LTTNG_CONDITION_STATUS_OK = 0,
	LTTNG_CONDITION_STATUS_ERROR = -1,
	LTTNG_CONDITION_STATUS_UNKNOWN = -2,
	LTTNG_CONDITION_STATUS_INVALID = -3,
	LTTNG_CONDITION_STATUS_UNSET = -4,
};

/*
 * Get the type of a condition.
 *
 * Returns the type of a condition on success, LTTNG_CONDITION_TYPE_UNKNOWN on
 * error.
 */
extern enum lttng_condition_type lttng_condition_get_type(
		const struct lttng_condition *condition);

/*
 * Destroy (frees) a condition object.
 */
extern void lttng_condition_destroy(struct lttng_condition *condition);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_H */
