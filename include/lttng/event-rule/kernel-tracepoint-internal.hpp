/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_TRACEPOINT_INTERNAL_H
#define LTTNG_EVENT_RULE_KERNEL_TRACEPOINT_INTERNAL_H

#include <common/macros.hpp>
#include <common/optional.hpp>
#include <common/payload-view.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/kernel-tracepoint.h>
#include <lttng/event.h>

struct lttng_event_rule_kernel_tracepoint {
	struct lttng_event_rule parent;

	/* Name pattern. */
	char *pattern;

	/* Filter. */
	char *filter_expression;

	/* internal use only. */
	struct {
		char *filter;
		struct lttng_bytecode *bytecode;
	} internal_filter;
};

struct lttng_event_rule_kernel_tracepoint_comm {
	/* Includes terminator `\0`. */
	uint32_t pattern_len;
	/* Includes terminator `\0`. */
	uint32_t filter_expression_len;
	/*
	 * Payload is composed of, in that order:
	 *   - pattern (null terminated),
	 *   - filter expression (null terminated),
	 */
	char payload[];
} LTTNG_PACKED;

ssize_t lttng_event_rule_kernel_tracepoint_create_from_payload(struct lttng_payload_view *view,
							       struct lttng_event_rule **rule);

#endif /* LTTNG_EVENT_RULE_KERNEL_TRACEPOINT_INTERNAL_H */
