/*
 * Copyright (C) 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_USER_TRACEPOINT_INTERNAL_H
#define LTTNG_EVENT_RULE_USER_TRACEPOINT_INTERNAL_H

#include <common/macros.hpp>
#include <common/optional.hpp>
#include <common/payload-view.hpp>

#include <lttng/domain.h>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/event.h>
#include <lttng/log-level-rule-internal.hpp>

struct lttng_event_rule_user_tracepoint {
	struct lttng_event_rule parent;

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

struct lttng_event_rule_user_tracepoint_comm {
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

ssize_t lttng_event_rule_user_tracepoint_create_from_payload(struct lttng_payload_view *view,
							     struct lttng_event_rule **rule);

#endif /* LTTNG_EVENT_RULE_USER_TRACEPOINT_INTERNAL_H */
