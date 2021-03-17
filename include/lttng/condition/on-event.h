/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_ON_EVENT_H
#define LTTNG_CONDITION_ON_EVENT_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_event_expr;
struct lttng_event_field_value;

enum lttng_evaluation_on_event_status {
	LTTNG_EVALUATION_ON_EVENT_STATUS_NONE = 1,
	LTTNG_EVALUATION_ON_EVENT_STATUS_OK = 0,
	LTTNG_EVALUATION_ON_EVENT_STATUS_INVALID = -1,
};

/**
 * On event conditions allows an action to be taken whenever an event matching
 * the on event is hit by the tracers.
 *
 * An on event condition can also specify a payload to be captured at runtime.
 * This is done via the capture descriptor.
 *
 * Note: the dynamic runtime capture of payload is only available for the
 *       trigger notification subsystem.
 */

/*
 * Create a newly allocated on event condition.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
extern struct lttng_condition *lttng_condition_on_event_create(
		struct lttng_event_rule *rule);

/*
 * Get the rule property of a on event condition.
 *
 * The caller does not assume the ownership of the returned rule. The
 * rule shall only be used for the duration of the condition's
 * lifetime.
 *
 * Returns LTTNG_CONDITION_STATUS_OK and a pointer to the condition's rule
 * on success, LTTNG_CONDITION_STATUS_INVALID if an invalid
 * parameter is passed. */
extern enum lttng_condition_status lttng_condition_on_event_get_rule(
		const struct lttng_condition *condition,
		const struct lttng_event_rule **rule);

/**
 * lttng_evaluation_on_event_hit are specialised lttng_evaluations which
 * allow users to query a number of properties resulting from the evaluation
 * of a condition which evaluated to true.
 *
 * The evaluation of a on event hit yields two different results:
 *    TEMPORARY - The name of the triggers associated with the condition.
 *    TODO - The captured event payload if any
 */

/*
 * Get the trigger name property of a on event hit evaluation.
 *
 * Returns LTTNG_EVALUATION_STATUS_OK on success and a trigger name
 * or LTTNG_EVALUATION_STATUS_INVALID if
 * an invalid parameter is passed.
 */
extern enum lttng_evaluation_status
lttng_evaluation_on_event_get_trigger_name(
		const struct lttng_evaluation *evaluation,
		const char **name);

/*
 * Sets `*field_val` to the array event field value of the on event
 * condition evaluation `evaluation` which contains its captured values.
 *
 * Returns:
 *
 * `LTTNG_EVALUATION_ON_EVENT_STATUS_OK`:
 *     Success.
 *
 *     `*field_val` is an array event field value with a length of at
 *     least one.
 *
 * `LTTNG_EVALUATION_ON_EVENT_STATUS_INVALID`:
 *     * `evaluation` is `NULL`.
 *     * The type of the condition of `evaluation` is not
 *       `LTTNG_CONDITION_TYPE_ON_EVENT`.
 *     * `field_val` is `NULL`.
 *
 * `LTTNG_EVALUATION_ON_EVENT_STATUS_NONE`:
 *     * The condition of `evaluation` has no capture descriptors.
 */
extern enum lttng_evaluation_on_event_status
lttng_evaluation_on_event_get_captured_values(
		const struct lttng_evaluation *evaluation,
		const struct lttng_event_field_value **field_val);

/*
 * Appends (transfering the ownership) the capture descriptor `expr` to
 * the on event condition `condition`.
 *
 * Returns:
 *
 * `LTTNG_CONDITION_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_CONDITION_STATUS_ERROR`:
 *     Memory error.
 *
 * `LTTNG_CONDITION_STATUS_INVALID`:
 *     * `condition` is `NULL`.
 *     * The type of `condition` is not
 *       `LTTNG_CONDITION_TYPE_ON_EVENT`.
 *     * `expr` is `NULL`.
 *     * `expr` is not a locator expression, that is, its type is not
 *       one of:
 *
 *       * `LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT`
 *
 * `LTTNG_CONDITION_STATUS_UNSUPPORTED`:
 *     * The associated event-rule does not support runtime capture.
 */
extern enum lttng_condition_status
lttng_condition_on_event_append_capture_descriptor(
		struct lttng_condition *condition,
		struct lttng_event_expr *expr);

/*
 * Sets `*count` to the number of capture descriptors in the on event
 * condition `condition`.
 *
 * Returns:
 *
 * `LTTNG_CONDITION_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_CONDITION_STATUS_INVALID`:
 *     * `condition` is `NULL`.
 *     * The type of `condition` is not
 *       `LTTNG_CONDITION_TYPE_ON_EVENT`.
 *     * `count` is `NULL`.
 */
extern enum lttng_condition_status
lttng_condition_on_event_get_capture_descriptor_count(
		const struct lttng_condition *condition, unsigned int *count);

/*
 * Returns the capture descriptor (borrowed) of the on event condition
 * `condition` at the index `index`, or `NULL` if:
 *
 * * `condition` is `NULL`.
 * * The type of `condition` is not
 *   `LTTNG_CONDITION_TYPE_ON_EVENT`.
 * * `index` is greater than or equal to the number of capture
 *   descriptors in `condition` (as returned by
 *   lttng_condition_on_event_get_capture_descriptor_count()).
 */
extern const struct lttng_event_expr *
lttng_condition_on_event_get_capture_descriptor_at_index(
		const struct lttng_condition *condition, unsigned int index);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_ON_EVENT_H */
