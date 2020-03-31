/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_EVENT_RULE_H
#define LTTNG_CONDITION_EVENT_RULE_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_event_expr;

/**
 * Event rule conditions allows an action to be taken whenever an event matching
 * the event rule is hit by the tracers.
 *
 * An event rule condition can also specify a payload to be captured at runtime.
 * This is done via the capture descriptor.
 *
 * Note: the dynamic runtime capture of payload is only available for the
 *       trigger notification subsystem.
 */

/*
 * Create a newly allocated event rule condition.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
extern struct lttng_condition *lttng_condition_event_rule_create(
		struct lttng_event_rule *rule);

/*
 * Get the rule property of a event rule condition.
 *
 * The caller does not assume the ownership of the returned rule. The
 * rule shall only be used for the duration of the condition's
 * lifetime.
 *
 * Returns LTTNG_CONDITION_STATUS_OK and a pointer to the condition's rule
 * on success, LTTNG_CONDITION_STATUS_INVALID if an invalid
 * parameter is passed. */
extern enum lttng_condition_status lttng_condition_event_rule_get_rule(
		 const struct lttng_condition *condition,
		const struct lttng_event_rule **rule);

/**
 * lttng_evaluation_event_rule_hit are specialised lttng_evaluations which
 * allow users to query a number of properties resulting from the evaluation
 * of a condition which evaluated to true.
 *
 * The evaluation of a event rule hit yields two different results:
 *    TEMPORARY - The name of the triggers associated with the condition.
 *    TODO - The captured event payload if any
 */

/*
 * Get the trigger name property of a event rule hit evaluation.
 *
 * Returns LTTNG_EVALUATION_STATUS_OK on success and a trigger name
 * or LTTNG_EVALUATION_STATUS_INVALID if
 * an invalid parameter is passed.
 */
extern enum lttng_evaluation_status
lttng_evaluation_event_rule_get_trigger_name(
		const struct lttng_evaluation *evaluation,
		const char **name);

/*
 * Appends (transfering the ownership) the capture descriptor `expr` to
 * the event rule condition `condition`.
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
 *       `LTTNG_CONDITION_TYPE_EVENT_RULE_HIT`.
 *     * `expr` is `NULL`.
 *     * `expr` is not a locator expression, that is, its type is not
 *       one of:
 *
 *       * `LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD`
 *       * `LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT`
 */
extern enum lttng_condition_status
lttng_condition_event_rule_append_capture_descriptor(
		struct lttng_condition *condition,
		struct lttng_event_expr *expr);

/*
 * Sets `*count` to the number of capture descriptors in the event rule
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
 *       `LTTNG_CONDITION_TYPE_EVENT_RULE_HIT`.
 *     * `count` is `NULL`.
 */
extern enum lttng_condition_status
lttng_condition_event_rule_get_capture_descriptor_count(
		const struct lttng_condition *condition, unsigned int *count);

/*
 * Returns the capture descriptor (borrowed) of the event rule condition
 * `condition` at the index `index`, or `NULL` if:
 *
 * * `condition` is `NULL`.
 * * The type of `condition` is not
 *   `LTTNG_CONDITION_TYPE_EVENT_RULE_HIT`.
 * * `index` is greater than or equal to the number of capture
 *   descriptors in `condition` (as returned by
 *   lttng_condition_event_rule_get_capture_descriptor_count()).
 */
extern const struct lttng_event_expr *
lttng_condition_event_rule_get_capture_descriptor_at_index(
		const struct lttng_condition *condition, unsigned int index);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_EVENT_RULE_H */
