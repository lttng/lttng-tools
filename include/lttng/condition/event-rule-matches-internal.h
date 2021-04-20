/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_ON_EVENT_INTERNAL_H
#define LTTNG_CONDITION_ON_EVENT_INTERNAL_H

#include <lttng/condition/condition-internal.h>
#include <common/buffer-view.h>
#include <common/macros.h>
#include <common/optional.h>
#include <lttng/condition/evaluation-internal.h>
#include <common/dynamic-array.h>
#include <lttng/event-field-value.h>

struct lttng_capture_descriptor {
	struct lttng_event_expr *event_expression;
	struct lttng_bytecode *bytecode;
};

struct lttng_condition_on_event {
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

struct lttng_evaluation_on_event {
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

LTTNG_HIDDEN
ssize_t lttng_condition_on_event_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **condition);

LTTNG_HIDDEN
enum lttng_condition_status
lttng_condition_on_event_borrow_rule_mutable(
		const struct lttng_condition *condition,
		struct lttng_event_rule **rule);

LTTNG_HIDDEN
void lttng_condition_on_event_set_error_counter_index(
		struct lttng_condition *condition, uint64_t error_counter_index);

LTTNG_HIDDEN
uint64_t lttng_condition_on_event_get_error_counter_index(
		const struct lttng_condition *condition);

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_on_event_create(
		const struct lttng_condition_on_event *condition,
		const char *capture_payload, size_t capture_payload_size,
		bool decode_capture_payload);

LTTNG_HIDDEN
ssize_t lttng_evaluation_on_event_create_from_payload(
		const struct lttng_condition_on_event *condition,
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation);

LTTNG_HIDDEN
enum lttng_error_code
lttng_condition_on_event_generate_capture_descriptor_bytecode(
		struct lttng_condition *condition);

LTTNG_HIDDEN
const struct lttng_bytecode *
lttng_condition_on_event_get_capture_bytecode_at_index(
		const struct lttng_condition *condition, unsigned int index);

#endif /* LTTNG_CONDITION_ON_EVENT_INTERNAL_H */
