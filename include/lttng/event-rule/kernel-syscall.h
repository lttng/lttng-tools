/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_SYSCALL_H
#define LTTNG_EVENT_RULE_KERNEL_SYSCALL_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_event_rule_kernel_syscall_emission_site {
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT = 0,
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY = 1,
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT = 2,
	LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_UNKNOWN = -1,
};

/*
 * Create a newly allocated kernel syscall event rule.
 *
 * The default pattern is '*'.
 * The default emission site is LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT.
 *
 * Returns a new event rule on success, NULL on failure. This event rule must be
 * destroyed using lttng_event_rule_destroy().
 */
LTTNG_EXPORT extern struct lttng_event_rule *lttng_event_rule_kernel_syscall_create(
	enum lttng_event_rule_kernel_syscall_emission_site emission_site);

/*
 * Set the name pattern of a kernel syscall event rule.
 *
 * Pattern can contain wildcard '*'. See man lttng-enable-event.
 *
 * The pattern is copied internally.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_syscall_set_name_pattern(struct lttng_event_rule *rule,
						 const char *pattern);

/*
 * Get the name pattern of a kernel syscall event rule.
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
lttng_event_rule_kernel_syscall_get_name_pattern(const struct lttng_event_rule *rule,
						 const char **pattern);

/*
 * Set the filter expression of a kernel syscall event rule.
 *
 * The expression is copied internally.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_event_rule_status
lttng_event_rule_kernel_syscall_set_filter(struct lttng_event_rule *rule, const char *expression);

/*
 * Get the filter expression of a kernel syscall event rule.
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
lttng_event_rule_kernel_syscall_get_filter(const struct lttng_event_rule *rule,
					   const char **expression);

/*
 * Get the emission site of a kernel syscall event rule.
 *
 * Returns a enum lttng_event_rule_kernel_syscall_emission_site.
 */
LTTNG_EXPORT extern enum lttng_event_rule_kernel_syscall_emission_site
lttng_event_rule_kernel_syscall_get_emission_site(const struct lttng_event_rule *rule);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_KERNEL_SYSCALL_H */
