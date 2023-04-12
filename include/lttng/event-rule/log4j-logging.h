/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_LOG4J_LOGGING_H
#define LTTNG_EVENT_RULE_LOG4J_LOGGING_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/event.h>
#include <lttng/log-level-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated log4j logging event rule.
 *
 * The default name pattern is '*'.
 *
 * Returns a new event rule on success, NULL on failure. This event rule must be
 * destroyed using lttng_event_rule_destroy().
 */
LTTNG_EXPORT extern struct lttng_event_rule *lttng_event_rule_log4j_logging_create(void);

/*
 * Set the name pattern of a log4j logging event rule.
 *
 * Pattern can contain wildcard '*'. See man lttng-enable-event.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j_logging_set_name_pattern(struct lttng_event_rule *rule, const char *pattern);

/*
 * Get the name pattern of a log4j logging event rule.
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
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j_logging_get_name_pattern(const struct lttng_event_rule *rule,
						const char **pattern);

/*
 * Set the filter expression of a log4j logging event rule.
 *
 * The expression is copied internally.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j_logging_set_filter(struct lttng_event_rule *rule, const char *expression);

/*
 * Get the filter expression of a log4j logging event rule.
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
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_log4j_logging_get_filter(const struct lttng_event_rule *rule,
					  const char **expression);

/*
 * Set the log level rule of a log4j logging event rule.
 *
 * The log level rule is copied internally.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_event_rule_status lttng_event_rule_log4j_logging_set_log_level_rule(
	struct lttng_event_rule *rule, const struct lttng_log_level_rule *log_level_rule);

/*
 * Get the log level rule of a log4j logging event rule.
 *
 * The caller does not assume the ownership of the returned log level rule. The
 * log level rule shall only only be used for the duration of the event rule's
 * lifetime, or before a different log level rule is set.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and sets the log level rule output
 * parameter on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter
 * is passed, or LTTNG_EVENT_RULE_STATUS_UNSET if a log level rule was not set prior
 * to this call.
 */
LTTNG_EXPORT extern enum lttng_event_rule_status lttng_event_rule_log4j_logging_get_log_level_rule(
	const struct lttng_event_rule *rule, const struct lttng_log_level_rule **log_level_rule);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_LOG4J_LOGGING_H */
