/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_EVENT_RULE_MATCHES_INTERNAL_H
#define LTTNG_CONDITION_EVENT_RULE_MATCHES_INTERNAL_H

#include <common/buffer-view.hpp>
#include <common/dynamic-array.hpp>
#include <common/macros.hpp>
#include <common/optional.hpp>

#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/evaluation-internal.hpp>
#include <lttng/event-field-value.h>

struct lttng_capture_descriptor {
	struct lttng_event_expr *event_expression;
	struct lttng_bytecode *bytecode;
};

struct lttng_condition_event_rule_matches {
	struct lttng_condition parent;
	struct lttng_event_rule *rule;

	/*
	 * Internal use only.
	 * Error accounting counter index.
	 */
	LTTNG_OPTIONAL(uint64_t) error_counter_index;

	/* Array of `struct lttng_capture_descriptor *`. */
	struct lttng_dynamic_pointer_array capture_descriptors;
};

struct lttng_evaluation_event_rule_matches {
	struct lttng_evaluation parent;

	/* MessagePack-encoded captured event field values. */
	struct lttng_dynamic_buffer capture_payload;

	/*
	 * The content of this array event field value is the decoded
	 * version of `capture_payload` above.
	 *
	 * This is a cache: it's not serialized/deserialized in
	 * communications from/to the library and the session daemon.
	 */
	struct lttng_event_field_value *captured_values;
};

ssize_t lttng_condition_event_rule_matches_create_from_payload(struct lttng_payload_view *view,
							       struct lttng_condition **condition);

enum lttng_condition_status
lttng_condition_event_rule_matches_borrow_rule_mutable(const struct lttng_condition *condition,
						       struct lttng_event_rule **rule);

void lttng_condition_event_rule_matches_set_error_counter_index(struct lttng_condition *condition,
								uint64_t error_counter_index);

uint64_t
lttng_condition_event_rule_matches_get_error_counter_index(const struct lttng_condition *condition);

struct lttng_evaluation *lttng_evaluation_event_rule_matches_create(
	const struct lttng_condition_event_rule_matches *condition,
	const char *capture_payload,
	size_t capture_payload_size,
	bool decode_capture_payload);

ssize_t lttng_evaluation_event_rule_matches_create_from_payload(
	const struct lttng_condition_event_rule_matches *condition,
	struct lttng_payload_view *view,
	struct lttng_evaluation **_evaluation);

enum lttng_error_code lttng_condition_event_rule_matches_generate_capture_descriptor_bytecode(
	struct lttng_condition *condition);

const struct lttng_bytecode *lttng_condition_event_rule_matches_get_capture_bytecode_at_index(
	const struct lttng_condition *condition, unsigned int index);

#endif /* LTTNG_CONDITION_EVENT_RULE_MATCHES_INTERNAL_H */
