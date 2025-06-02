/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

/*!
@addtogroup api_trigger_cond
@{
*/

/*!
@struct lttng_evaluation

@brief
    Trigger condition evaluation (opaque type).
*/
struct lttng_evaluation;

/*!
@brief
    Return type of trigger condition evaluation API functions.
*/
enum lttng_evaluation_status {
	/// Success.
	LTTNG_EVALUATION_STATUS_OK = 0,

	/* Unused for the moment */
	LTTNG_EVALUATION_STATUS_ERROR = -1,

	/// Unsatisfied precondition.
	LTTNG_EVALUATION_STATUS_INVALID = -2,

	/* Unused for the moment */
	LTTNG_EVALUATION_STATUS_UNKNOWN = -3,

	/* Unused for the moment */
	LTTNG_EVALUATION_STATUS_UNSET = -4,
};

/*!
@brief
    Returns the condition type of the trigger condition evaluation
    \lt_p{evaluation}.

@param[in] evaluation
    Trigger condition evaluation of which to get the condition type.

@returns
    Type of \lt_p{evaluation}.

@pre
    @lt_pre_not_null{evaluation}
*/
LTTNG_EXPORT extern enum lttng_condition_type
lttng_evaluation_get_type(const struct lttng_evaluation *evaluation);

/*!
@brief
    Destroys the trigger condition evaluation \lt_p{evaluation}.

@param[in] evaluation
    @parblock
    Trigger condition evaluation to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_evaluation_destroy(struct lttng_evaluation *evaluation);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVALUATION_H */
