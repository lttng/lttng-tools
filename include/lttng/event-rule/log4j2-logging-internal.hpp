/*
 * SPDX-FileCopyrightText: 2024 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_LOG4J2_LOGGING_INTERNAL_H
#define LTTNG_EVENT_RULE_LOG4J2_LOGGING_INTERNAL_H

#include <common/macros.hpp>
#include <common/optional.hpp>
#include <common/payload-view.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/log4j2-logging.h>
#include <lttng/event.h>
#include <lttng/log-level-rule-internal.hpp>

#define LTTNG_LOG4J2_EVENT_RULE_AT_LEAST_AS_SEVERE_AS_OP "<="

struct lttng_event_rule_log4j2_logging {
	struct lttng_event_rule parent;

	/* Name pattern. */
	char *pattern;

	/* Filter. */
	char *filter_expression;

	/* Log level. */
	struct lttng_log_level_rule *log_level_rule;

	/* internal use only. */
	struct {
		char *filter;
		struct lttng_bytecode *bytecode;
	} internal_filter;
};

struct lttng_event_rule_log4j2_logging_comm {
	/* Includes terminator `\0`. */
	uint32_t pattern_len;
	/* Includes terminator `\0`. */
	uint32_t filter_expression_len;
	/*  enum lttng_log_level_rule_comm + payload if any */
	uint32_t log_level_rule_len;
	/*
	 * Payload is composed of, in that order:
	 *   - pattern (null terminated),
	 *   - filter expression (null terminated),
	 *   - log level rule serialized object,
	 */
	char payload[];
} LTTNG_PACKED;

ssize_t lttng_event_rule_log4j2_logging_create_from_payload(struct lttng_payload_view *view,
							    struct lttng_event_rule **rule);

#endif /* LTTNG_EVENT_RULE_LOG4J2_LOGGING_INTERNAL_H */
