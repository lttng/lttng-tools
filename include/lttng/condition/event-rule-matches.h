/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_EVENT_RULE_MATCHES_H
#define LTTNG_CONDITION_EVENT_RULE_MATCHES_H

#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_event_expr;
struct lttng_event_field_value;

enum lttng_evaluation_event_rule_matches_status {
	LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_NONE = 1,
	LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_OK = 0,
	LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_INVALID = -1,
};

/**
 * Event Rule Matches conditions allows an action to be taken whenever an event
 * matching the Event Rule Matches is hit by the tracers.
 *
 * An Event Rule Matches condition can also specify a payload to be captured at
 * runtime. This is done via the capture descriptor.
 *
 * Note: the dynamic runtime capture of payload is only available for the
 *       trigger notification subsystem.
 */

/*
 * Create a newly allocated Event Rule Matches condition.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
LTTNG_EXPORT extern struct lttng_condition *
lttng_condition_event_rule_matches_create(struct lttng_event_rule *rule);

/*
 * Get the rule property of an Event Rule Matches condition.
 *
 * The caller does not assume the ownership of the returned rule. The
 * rule shall only be used for the duration of the condition's
 * lifetime.
 *
 * Returns LTTNG_CONDITION_STATUS_OK and a pointer to the condition's rule
 * on success, LTTNG_CONDITION_STATUS_INVALID if an invalid
 * parameter is passed. */
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_event_rule_matches_get_rule(const struct lttng_condition *condition,
					    const struct lttng_event_rule **rule);

/**
 * lttng_evaluation_event_rule_matches_hit are specialised lttng_evaluations
 * which allow users to query a number of properties resulting from the
 * evaluation of a condition which evaluated to true.
 *
 * The evaluation of an Event Rule Matches condition contains the captured event
 * payload fields that were specified by the condition.
 */

/*
 * Sets `*field_val` to the array event field value of the Event Rule Matches
 * condition evaluation `evaluation` which contains its captured values.
 *
 * Returns:
 *
 * `LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_OK`:
 *     Success.
 *
 *     `*field_val` is an array event field value with a length of at
 *     least one.
 *
 * `LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_INVALID`:
 *     * `evaluation` is `NULL`.
 *     * The type of the condition of `evaluation` is not
 *       `LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES`.
 *     * `field_val` is `NULL`.
 *
 * `LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_NONE`:
 *     * The condition of `evaluation` has no capture descriptors.
 */
LTTNG_EXPORT extern enum lttng_evaluation_event_rule_matches_status
lttng_evaluation_event_rule_matches_get_captured_values(
	const struct lttng_evaluation *evaluation,
	const struct lttng_event_field_value **field_val);

/*
 * Appends (transfering the ownership) the capture descriptor `expr` to
 * the Event Rule Matches condition `condition`.
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
 *       `LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES`.
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
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_event_rule_matches_append_capture_descriptor(struct lttng_condition *condition,
							     struct lttng_event_expr *expr);

/*
 * Sets `*count` to the number of capture descriptors in the Event Rule Matches
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
 *       `LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES`.
 *     * `count` is `NULL`.
 */
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_event_rule_matches_get_capture_descriptor_count(
	const struct lttng_condition *condition, unsigned int *count);

/*
 * Returns the capture descriptor (borrowed) of the Event Rule Matches condition
 * `condition` at the index `index`, or `NULL` if:
 *
 * * `condition` is `NULL`.
 * * The type of `condition` is not
 *   `LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES`.
 * * `index` is greater than or equal to the number of capture
 *   descriptors in `condition` (as returned by
 *   lttng_condition_event_rule_matches_get_capture_descriptor_count()).
 */
LTTNG_EXPORT extern const struct lttng_event_expr *
lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
	const struct lttng_condition *condition, unsigned int index);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_EVENT_RULE_MATCHES_H */
