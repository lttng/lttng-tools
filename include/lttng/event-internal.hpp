/*
 * event-internal.h
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_INTERNAL_H
#define LTTNG_EVENT_INTERNAL_H

#include <common/macros.hpp>

#include <lttng/event.h>
#include <lttng/lttng-error.h>

struct lttng_event_exclusion;
struct lttng_userspace_probe_location;
struct lttng_dynamic_buffer;
struct lttng_buffer_view;

struct lttng_event_comm {
	int8_t event_type;
	int8_t loglevel_type;
	int32_t loglevel;
	int8_t enabled;
	int32_t pid;
	uint32_t flags;

	/* Payload. */
	/* Includes terminator `\0`. */
	uint32_t name_len;
	uint32_t exclusion_count;
	/* Includes terminator `\0`. */
	uint32_t filter_expression_len;
	uint32_t bytecode_len;

	/* Type specific payload. */
	uint32_t userspace_probe_location_len;
	uint32_t lttng_event_probe_attr_len;
	uint32_t lttng_event_function_attr_len;

	/*
	 * Contain:
	 * - name [name_len],
	 * - exclusions if any
	 * - char filter_expression[filter_expression_len],
	 * - unsigned char filter_bytecode[bytecode_len],
	 * - userspace probe location [userspace_probe_location_len],
	 * - probe or ftrace based on event type.
	 */

	char payload[];
} LTTNG_PACKED;

struct lttng_event_exclusion_comm {
	/* Includes terminator `\0`. */
	uint32_t len;
	char payload[];
} LTTNG_PACKED;

struct lttng_event_probe_attr_comm {
	uint64_t addr;
	uint64_t offset;
	/* Includes terminator `\0`. */
	uint32_t symbol_name_len;

	char payload[];
} LTTNG_PACKED;

struct lttng_event_function_attr_comm {
	/* Includes terminator `\0`. */
	uint32_t symbol_name_len;

	char payload[];
} LTTNG_PACKED;

struct lttng_event_context_comm {
	uint32_t type;
	/*
	 * Depending on the type.
	 * For:
	 *  - LTTNG_EVENT_CONTEXT_APP_CONTEXT.
	 *
	 *  -> struct lttng_event_context_app_comm
	 *
	 * For
	 *  - LTTNG_EVENT_CONTEXT_PERF_COUNTER,
	 *  - LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER,
	 *  - LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER.
	 *
	 *  -> struct lttng_event_context_perf_counter_comm
	 *
	 *  Other type -> no payload.
	 */
	char payload[];
} LTTNG_PACKED;

struct lttng_event_context_perf_counter_comm {
	uint32_t type;
	uint64_t config;
	/* Includes terminator `\0`. */
	uint32_t name_len;
	/*
	 * char name [name_len]
	 */
	char payload[];
} LTTNG_PACKED;

struct lttng_event_context_app_comm {
	/* Includes terminator `\0`. */
	uint32_t provider_name_len;
	/* Includes terminator `\0`. */
	uint32_t ctx_name_len;
	/*
	 * provider name [provider_name_len]
	 * ctx name [ctx_name_len]
	 */
	char payload[];
} LTTNG_PACKED;

struct lttng_event_field_comm {
	uint8_t type;
	uint8_t nowrite;
	/* Includes terminator `\0`. */
	uint32_t name_len;
	uint32_t event_len;

	/*
	 * - name [name_len]
	 * - lttng_event object
	 */
	char payload[];
} LTTNG_PACKED;

struct lttng_event_extended {
	/*
	 * exclusions and filter_expression are only set when the lttng_event
	 * was created/allocated by a list operation. These two elements must
	 * not be free'd as they are part of the same contiguous buffer that
	 * contains all events returned by the listing.
	 */
	char *filter_expression;
	struct {
		unsigned int count;
		/* Array of strings of fixed LTTNG_SYMBOL_NAME_LEN length. */
		char *strings;
	} exclusions;
	struct lttng_userspace_probe_location *probe_location;
};

struct lttng_event *lttng_event_copy(const struct lttng_event *event);

ssize_t lttng_event_create_from_payload(struct lttng_payload_view *view,
					struct lttng_event **out_event,
					struct lttng_event_exclusion **out_exclusion,
					char **out_filter_expression,
					struct lttng_bytecode **out_bytecode);

int lttng_event_serialize(const struct lttng_event *event,
			  unsigned int exclusion_count,
			  char **exclusion_list,
			  char *filter_expression,
			  size_t bytecode_len,
			  struct lttng_bytecode *bytecode,
			  struct lttng_payload *payload);

ssize_t lttng_event_context_create_from_payload(struct lttng_payload_view *view,
						struct lttng_event_context **event_ctx);

int lttng_event_context_serialize(struct lttng_event_context *context,
				  struct lttng_payload *payload);

void lttng_event_context_destroy(struct lttng_event_context *context);

enum lttng_error_code lttng_events_create_and_flatten_from_payload(struct lttng_payload_view *view,
								   unsigned int count,
								   struct lttng_event **events);

ssize_t lttng_event_field_create_from_payload(struct lttng_payload_view *view,
					      struct lttng_event_field **field);

int lttng_event_field_serialize(const struct lttng_event_field *field,
				struct lttng_payload *payload);

enum lttng_error_code lttng_event_fields_create_and_flatten_from_payload(
	struct lttng_payload_view *view, unsigned int count, struct lttng_event_field **fields);

#endif /* LTTNG_EVENT_INTERNAL_H */
