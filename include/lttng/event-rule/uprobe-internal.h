/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_UPROBE_INTERNAL_H
#define LTTNG_EVENT_RULE_UPROBE_INTERNAL_H

#include <common/payload-view.h>
#include <common/macros.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/uprobe.h>

struct lttng_event_rule_uprobe {
	struct lttng_event_rule parent;
	char *name;
	struct lttng_userspace_probe_location *location;
};

struct lttng_event_rule_uprobe_comm {
	/* Includes terminator `\0`. */
	uint32_t name_len;
	/* Includes terminator `\0`. */
	uint32_t location_len;
	/*
	 * Payload is composed of, in that order:
	 *   - name (null terminated),
	 *   - user space probe location object.
	 */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_event_rule_uprobe_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **rule);

LTTNG_HIDDEN
struct lttng_userspace_probe_location *
lttng_event_rule_uprobe_get_location_mutable(
		const struct lttng_event_rule *rule);

#endif /* LTTNG_EVENT_RULE_UPROBE_INTERNAL_H */
