/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_UPROBE_H
#define LTTNG_EVENT_RULE_UPROBE_H

#include <lttng/event-rule/event-rule.h>
#include <lttng/userspace-probe.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a newly allocated uprobe event rule.
 *
 * Returns a new event rule on success, NULL on failure. This event rule must be
 * destroyed using lttng_event_rule_destroy().
 */
extern struct lttng_event_rule *lttng_event_rule_uprobe_create(void);

/*
 * Set the location of a uprobe event rule.
 *
 * The location is copied internally.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status lttng_event_rule_uprobe_set_location(
		struct lttng_event_rule *rule,
		const struct lttng_userspace_probe_location *location);

/*
 * Get the location of a uprobe event rule.
 *
 * The caller does not assume the ownership of the returned location.
 * The location shall only be used for the duration of the event
 * rule's lifetime, or before a different location is set.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and a pointer to the event rule's location
 * on success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter is
 * passed, or LTTNG_EVENT_RULE_STATUS_UNSET if a location was not set prior to
 * this call.
 */
extern enum lttng_event_rule_status lttng_event_rule_uprobe_get_location(
		const struct lttng_event_rule *rule,
		const struct lttng_userspace_probe_location **location);

/*
 * Set the name of a uprobe event rule.
 *
 * The name is copied internally.
 *
 * Return LTTNG_EVENT_RULE_STATUS_OK on success, LTTNG_EVENT_RULE_STATUS_INVALID
 * if invalid parameters are passed.
 */
extern enum lttng_event_rule_status lttng_event_rule_uprobe_set_name(
		struct lttng_event_rule *rule, const char *name);

/*
 * Get the name of a uprobe event rule.
 *
 * The caller does not assume the ownership of the returned name.
 * The name shall only only be used for the duration of the event
 * rule's lifetime, or before a different name is set.
 *
 * Returns LTTNG_EVENT_RULE_STATUS_OK and a pointer to the event rule's name on
 * success, LTTNG_EVENT_RULE_STATUS_INVALID if an invalid parameter is passed,
 * or LTTNG_EVENT_RULE_STATUS_UNSET if a name was not set prior to this call.
 */
extern enum lttng_event_rule_status lttng_event_rule_uprobe_get_name(
		const struct lttng_event_rule *rule, const char **name);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_RULE_UPROBE_H */
