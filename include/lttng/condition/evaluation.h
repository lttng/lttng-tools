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

#ifndef LTTNG_EVALUATION_H
#define LTTNG_EVALUATION_H

#include <lttng/condition/condition.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_evaluation;

enum lttng_evaluation_status {
	LTTNG_EVALUATION_STATUS_OK = 0,
	LTTNG_EVALUATION_STATUS_ERROR = -1,
	LTTNG_EVALUATION_STATUS_INVALID = -2,
	LTTNG_EVALUATION_STATUS_UNKNOWN = -2,
	LTTNG_EVALUATION_STATUS_UNSET = -3,
};

extern enum lttng_condition_type lttng_evaluation_get_type(
		const struct lttng_evaluation *evaluation);

extern void lttng_evaluation_destroy(struct lttng_evaluation *evaluation);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVALUATION_H */
