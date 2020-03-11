/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_SYSCALL_H
#define LTTNG_EVENT_RULE_SYSCALL_H

#include <lttng/event-rule/event-rule.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated syscall event rule.
 *
 * Returns a new event rule on success, NULL on failure. This event rule must be
 * destroyed using lttng_event_rule_destroy().
 */
extern struct lttng_event_rule *lttng_event_rule_syscall_create(void);

/*
 * Set the pattern of a syscall event rule.
 *
 * Pattern can contain wildcard '*'. See man lttng-enable-event.
 *
 * The pattern is copied internally.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status lttng_event_rule_syscall_set_pattern(
		struct lttng_event_rule *rule, const char *pattern);

/*
 * Get the pattern of a syscall event rule.
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
extern enum lttng_event_rule_status lttng_event_rule_syscall_get_pattern(
		const struct lttng_event_rule *rule, const char **pattern);

/*
 * Set the filter expression of a syscall event rule.
 *
 * The expression is copied internally.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status lttng_event_rule_syscall_set_filter(
		struct lttng_event_rule *rule, const char *expression);

/*
 * Get the filter expression of a syscall event rule.
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
extern enum lttng_event_rule_status lttng_event_rule_syscall_get_filter(
		const struct lttng_event_rule *rule, const char **expression);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_SYSCALL_H */
