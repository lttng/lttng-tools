/*
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_KPROBE_INTERNAL_H
#define LTTNG_EVENT_RULE_KERNEL_KPROBE_INTERNAL_H

#include <common/macros.hpp>
#include <common/payload-view.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/kernel-kprobe.h>

/*
 * Determines the instrumentation behavior of a kernel kprobe event rule.
 *
 * LOCATION: Instrument at the specified location only (kprobe, entry only).
 *           This corresponds to LTTNG_EVENT_PROBE.
 *
 * ENTRY_EXIT: Instrument at both entry and exit of the function at the
 *             specified location (kretprobe). This corresponds to
 *             LTTNG_EVENT_FUNCTION.
 */
enum lttng_event_rule_kernel_kprobe_instrumentation_site {
	LTTNG_EVENT_RULE_KERNEL_KPROBE_INSTRUMENTATION_SITE_LOCATION = 0,
	LTTNG_EVENT_RULE_KERNEL_KPROBE_INSTRUMENTATION_SITE_ENTRY_EXIT = 1,
};

struct lttng_event_rule_kernel_kprobe {
	struct lttng_event_rule parent;
	char *name;
	struct lttng_kernel_probe_location *location;
	enum lttng_event_rule_kernel_kprobe_instrumentation_site instrumentation_site;
};

struct lttng_event_rule_kernel_kprobe_comm {
	/* Includes terminator `\0`. */
	uint32_t name_len;
	uint32_t location_len;
	uint32_t instrumentation_site;
	/*
	 * Payload is composed of, in that order:
	 *   - name (null terminated),
	 *   - kernel probe location object.
	 */
	char payload[];
} LTTNG_PACKED;

ssize_t lttng_event_rule_kernel_kprobe_create_from_payload(struct lttng_payload_view *payload,
							   struct lttng_event_rule **rule);

void lttng_event_rule_kernel_kprobe_set_instrumentation_site(
	struct lttng_event_rule *rule,
	enum lttng_event_rule_kernel_kprobe_instrumentation_site site);

enum lttng_event_rule_kernel_kprobe_instrumentation_site
lttng_event_rule_kernel_kprobe_get_instrumentation_site(const struct lttng_event_rule *rule);

#endif /* LTTNG_EVENT_RULE_KERNEL_KPROBE_INTERNAL_H */
