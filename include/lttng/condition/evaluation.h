/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVALUATION_H
#define LTTNG_EVALUATION_H

#include <lttng/condition/condition.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_evaluation;

enum lttng_evaluation_status {
	LTTNG_EVALUATION_STATUS_OK = 0,
	LTTNG_EVALUATION_STATUS_ERROR = -1,
	LTTNG_EVALUATION_STATUS_INVALID = -2,
	LTTNG_EVALUATION_STATUS_UNKNOWN = -3,
	LTTNG_EVALUATION_STATUS_UNSET = -4,
};

/*
 * Get the condition type associated with an evaluation.
 *
 * Returns the type of a condition on success, LTTNG_CONDITION_TYPE_UNKNOWN on
 * error.
 */
LTTNG_EXPORT extern enum lttng_condition_type
lttng_evaluation_get_type(const struct lttng_evaluation *evaluation);

/*
 * Destroy (frees) an evaluation object.
 */
LTTNG_EXPORT extern void lttng_evaluation_destroy(struct lttng_evaluation *evaluation);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVALUATION_H */
