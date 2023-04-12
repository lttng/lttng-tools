/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_RULE_KERNEL_SYSCALL_INTERNAL_H
#define LTTNG_EVENT_RULE_KERNEL_SYSCALL_INTERNAL_H

#include <common/macros.hpp>
#include <common/payload-view.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/kernel-syscall.h>

struct lttng_event_rule_kernel_syscall {
	struct lttng_event_rule parent;
	enum lttng_event_rule_kernel_syscall_emission_site emission_site;
	char *pattern;
	char *filter_expression;

	/* Internal use only. */
	struct {
		char *filter;
		struct lttng_bytecode *bytecode;
	} internal_filter;
};

struct lttng_event_rule_kernel_syscall_comm {
	uint32_t emission_site;
	/* Includes terminator `\0`. */
	uint32_t pattern_len;
	/* Includes terminator `\0`. */
	uint32_t filter_expression_len;
	/*
	 * Payload is composed of, in that order:
	 *   - Pattern (null terminated),
	 *   - Filter expression (null terminated).
	 */
	char payload[];
} LTTNG_PACKED;

ssize_t lttng_event_rule_kernel_syscall_create_from_payload(struct lttng_payload_view *view,
							    struct lttng_event_rule **rule);

const char *lttng_event_rule_kernel_syscall_emission_site_str(
	enum lttng_event_rule_kernel_syscall_emission_site emission_site);

#endif /* LTTNG_EVENT_RULE_KERNEL_SYSCALL_INTERNAL_H */
