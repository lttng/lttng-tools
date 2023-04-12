/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
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

struct lttng_event_rule_kernel_kprobe {
	struct lttng_event_rule parent;
	char *name;
	struct lttng_kernel_probe_location *location;
};

struct lttng_event_rule_kernel_kprobe_comm {
	/* Includes terminator `\0`. */
	uint32_t name_len;
	uint32_t location_len;
	/*
	 * Payload is composed of, in that order:
	 *   - name (null terminated),
	 *   - kernel probe location object.
	 */
	char payload[];
} LTTNG_PACKED;

ssize_t lttng_event_rule_kernel_kprobe_create_from_payload(struct lttng_payload_view *payload,
							   struct lttng_event_rule **rule);

#endif /* LTTNG_EVENT_RULE_KERNEL_KPROBE_INTERNAL_H */
