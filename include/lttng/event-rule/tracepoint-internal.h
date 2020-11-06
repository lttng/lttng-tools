/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_TRACEPOINT_INTERNAL_H
#define LTTNG_EVENT_RULE_TRACEPOINT_INTERNAL_H

#include <common/payload-view.h>
#include <common/macros.h>
#include <common/optional.h>
#include <lttng/domain.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/tracepoint.h>
#include <lttng/event.h>
#include <lttng/log-level-rule-internal.h>

struct lttng_event_rule_tracepoint {
	struct lttng_event_rule parent;

	/* Domain. */
	enum lttng_domain_type domain;

	/* Name pattern. */
	char *pattern;

	/* Filter. */
	char *filter_expression;

	/* Log level. */
	struct lttng_log_level_rule *log_level_rule;

	/* Exclusions. */
	struct lttng_dynamic_pointer_array exclusions;

	/* internal use only. */
	struct {
		char *filter;
		struct lttng_bytecode *bytecode;
	} internal_filter;
};

struct lttng_event_rule_tracepoint_comm {
	/* enum lttng_domain_type. */
	int8_t domain_type;
	/* Includes terminator `\0`. */
	uint32_t pattern_len;
	/* Includes terminator `\0`. */
	uint32_t filter_expression_len;
	/*  enum lttng_log_level_rule_comm + payload if any */
	uint32_t log_level_rule_len;
	uint32_t exclusions_count;
	uint32_t exclusions_len;
	/*
	 * Payload is composed of, in that order:
	 *   - pattern (null terminated),
	 *   - filter expression (null terminated),
	 *   - log level rule serialized object,
	 *   - exclusions (32 bit length + null terminated string).
	 */
	char payload[];
} LTTNG_PACKED;

LTTNG_HIDDEN
ssize_t lttng_event_rule_tracepoint_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **rule);

#endif /* LTTNG_EVENT_RULE_TRACEPOINT_INTERNAL_H */
