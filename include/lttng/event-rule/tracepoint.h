/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_TRACEPOINT_H
#define LTTNG_EVENT_RULE_TRACEPOINT_H

#include <lttng/domain.h>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated tracepoint event rule.
 *
 * Returns a new event rule on success, NULL on failure. This event rule must be
 * destroyed using lttng_event_rule_destroy().
 */
extern struct lttng_event_rule *lttng_event_rule_tracepoint_create(
		enum lttng_domain_type domain);

/*
 * Set the pattern of a tracepoint event rule.
 *
 * Pattern can contain wildcard '*'. See man lttng-enable-event.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_set_pattern(
		struct lttng_event_rule *rule, const char *pattern);

/*
 * Get the pattern of a tracepoint event rule.
 *
 * The caller does not assume the ownership of the returned pattern. The
 * pattern shall only only be used for the duration of the event rule's
 * lifetime, or before a different pattern is set.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and a pointer to the event rule's pattern
 * on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid
 * parameter is passed, or LTTNG_EVENT_RULE_STATUS_UNSET if a pattern
 * was not set prior to this call.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_get_pattern(
		const struct lttng_event_rule *rule, const char **pattern);

/*
 * Get the domain type of a tracepoint event rule.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and sets the domain type output parameter
 * on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter is
 * passed, or LTTNG_EVENT_RULE_STATUS_UNSET if a pattern was not set prior to
 * this call.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_get_domain_type(
		const struct lttng_event_rule *rule,
		enum lttng_domain_type *type);

/*
 * Set the filter expression of a tracepoint event rule.
 *
 * The expression is copied internally.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_set_filter(
		struct lttng_event_rule *rule, const char *expression);

/*
 * Get the filter expression of a tracepoint event rule.
 *
 * The caller does not assume the ownership of the returned filter expression.
 * The filter expression shall only only be used for the duration of the event
 * rule's lifetime, or before a different filter expression is set.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and a pointer to the event rule's filter
 * expression on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid
 * parameter is passed, or LTTNG_EVENT_RULE_STATUS_UNSET if a filter expression
 * was not set prior to this call.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_get_filter(
		const struct lttng_event_rule *rule, const char **expression);

/*
 * Set the single log level of a tracepoint event rule.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_set_log_level(
		struct lttng_event_rule *rule, int level);

/*
 * Set the log level range lower bound of a tracepoint event rule.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status
lttng_event_rule_tracepoint_set_log_level_range_lower_bound(
		struct lttng_event_rule *rule, int level);

/*
 * Set the log level to all of a tracepoint event rule.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status
lttng_event_rule_tracepoint_set_log_level_all(struct lttng_event_rule *rule);

/*
 * Get the log level type of a tracepoint event rule.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and sets the log level type output
 * parameter on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter
 * is passed, or LTTNG_EVENT_RULE_STATUS_UNSET if a log level was not set prior
 * to this call.
 */
extern enum lttng_event_rule_status
lttng_event_rule_tracepoint_get_log_level_type(
		const struct lttng_event_rule *rule,
		enum lttng_loglevel_type *type);

/*
 * Get the log level of a tracepoint event rule.
 *
 * For range log level , the lower bound log level is returned.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and sets the log level output parameter
 * on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter is
 * passed, or LTTNG_EVENT_RULE_STATUS_UNSET if a log level was not set prior to
 * this call.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_get_log_level(
		const struct lttng_event_rule *rule, int *level);

/*
 * Add an exclusion to the set of exclusion of an event rule.
 *
 * The passed exclusion will be copied to the event_rule.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK on success,
 * LTTNG_EVENT_RULE_STATUS_INVALID if invalid parameters are passed, or
 * LTTNG_EVENT_RULE_STATUS_UNSUPPORTED if this property is not supported by the
 * domain.
 */
extern enum lttng_event_rule_status lttng_event_rule_tracepoint_add_exclusion(
		struct lttng_event_rule *rule,
		const char *exclusion);

/*
 * Get the exclusions property count of an event rule.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and sets the count output parameter
 * on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter is
 * passed.
 */
extern enum lttng_event_rule_status
lttng_event_rule_tracepoint_get_exclusions_count(
		const struct lttng_event_rule *rule, unsigned int *count);

/*
 * Get the event rule exclusion at the given index.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and sets the exclusion output parameter
 * on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter is
 * passed.
 */
extern enum lttng_event_rule_status
lttng_event_rule_tracepoint_get_exclusion_at_index(
		const struct lttng_event_rule *rule,
		unsigned int index,
		const char **exclusion);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_TRACEPOINT_H */
