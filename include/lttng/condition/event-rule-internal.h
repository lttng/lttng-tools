/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_EVENT_RULE_INTERNAL_H
#define LTTNG_CONDITION_EVENT_RULE_INTERNAL_H

#include <lttng/condition/condition-internal.h>
#include <common/buffer-view.h>
#include <common/macros.h>
#include <lttng/condition/evaluation-internal.h>

struct lttng_condition_event_rule {
	struct lttng_condition parent;
	struct lttng_event_rule *rule;
};

struct lttng_condition_event_rule_comm {
	/* length excludes the header's length. */
	uint32_t event_rule_length;
	/* Event rule follows. */
	char payload[];
} LTTNG_PACKED;

struct lttng_evaluation_event_rule {
	struct lttng_evaluation parent;
	char *name;
};

struct lttng_evaluation_event_rule_comm {
	/* Includes the null terminator. */
	uint32_t trigger_name_length;
	/* Trigger name. */
	char payload[];
} LTTNG_PACKED;


LTTNG_HIDDEN
ssize_t lttng_condition_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **condition);

LTTNG_HIDDEN
enum lttng_condition_status
lttng_condition_event_rule_borrow_rule_mutable(
		const struct lttng_condition *condition,
		struct lttng_event_rule **rule);

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_event_rule_create(
		const char* trigger_name);

LTTNG_HIDDEN
ssize_t lttng_evaluation_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation);

#endif /* LTTNG_CONDITION_EVENT_RULE_INTERNAL_H */
