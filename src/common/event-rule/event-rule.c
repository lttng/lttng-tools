/*
 * Copyright (C) 2019 Jonathan Rajotte
 * <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <common/macros.h>
#include <common/mi-lttng.h>
#include <common/payload-view.h>
#include <common/payload.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/jul-logging-internal.h>
#include <lttng/event-rule/kernel-kprobe-internal.h>
#include <lttng/event-rule/kernel-syscall-internal.h>
#include <lttng/event-rule/kernel-tracepoint-internal.h>
#include <lttng/event-rule/kernel-uprobe-internal.h>
#include <lttng/event-rule/log4j-logging-internal.h>
#include <lttng/event-rule/python-logging-internal.h>
#include <lttng/event-rule/user-tracepoint-internal.h>
#include <stdbool.h>

enum lttng_event_rule_type lttng_event_rule_get_type(
		const struct lttng_event_rule *event_rule)
{
	return event_rule ? event_rule->type : LTTNG_EVENT_RULE_TYPE_UNKNOWN;
}

LTTNG_HIDDEN
enum lttng_domain_type lttng_event_rule_get_domain_type(
		const struct lttng_event_rule *event_rule)
{
	enum lttng_domain_type domain_type = LTTNG_DOMAIN_NONE;

	switch (lttng_event_rule_get_type(event_rule)) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		domain_type = LTTNG_DOMAIN_UST;
		break;
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		domain_type = LTTNG_DOMAIN_JUL;
		break;
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		domain_type = LTTNG_DOMAIN_LOG4J;
		break;
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		domain_type = LTTNG_DOMAIN_PYTHON;
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		domain_type = LTTNG_DOMAIN_KERNEL;
		break;
	case LTTNG_EVENT_RULE_TYPE_UNKNOWN:
		domain_type = LTTNG_DOMAIN_NONE;
		break;
	}

	return domain_type;
}

static void lttng_event_rule_release(struct urcu_ref *ref)
{
	struct lttng_event_rule *event_rule =
			container_of(ref, typeof(*event_rule), ref);

	LTTNG_ASSERT(event_rule->destroy);
	event_rule->destroy(event_rule);
}

void lttng_event_rule_destroy(struct lttng_event_rule *event_rule)
{
	lttng_event_rule_put(event_rule);
}

LTTNG_HIDDEN
bool lttng_event_rule_validate(const struct lttng_event_rule *event_rule)
{
	bool valid;

	if (!event_rule) {
		valid = false;
		goto end;
	}

	if (!event_rule->validate) {
		/* Sub-class guarantees that it can never be invalid. */
		valid = true;
		goto end;
	}

	valid = event_rule->validate(event_rule);
end:
	return valid;
}

LTTNG_HIDDEN
int lttng_event_rule_serialize(const struct lttng_event_rule *event_rule,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_event_rule_comm event_rule_comm = {};

	if (!event_rule) {
		ret = -1;
		goto end;
	}

	event_rule_comm.event_rule_type = (int8_t) event_rule->type;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &event_rule_comm, sizeof(event_rule_comm));
	if (ret) {
		goto end;
	}

	ret = event_rule->serialize(event_rule, payload);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

LTTNG_HIDDEN
bool lttng_event_rule_is_equal(const struct lttng_event_rule *a,
		const struct lttng_event_rule *b)
{
	bool is_equal = false;

	if (!a || !b) {
		goto end;
	}

	if (a->type != b->type) {
		goto end;
	}

	if (a == b) {
		is_equal = true;
		goto end;
	}

	is_equal = a->equal ? a->equal(a, b) : true;
end:
	return is_equal;
}

LTTNG_HIDDEN
ssize_t lttng_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_event_rule **event_rule)
{
	ssize_t ret, consumed = 0;
	event_rule_create_from_payload_cb create_from_payload = NULL;
	const struct lttng_event_rule_comm *event_rule_comm;
	const struct lttng_payload_view event_rule_comm_view =
			lttng_payload_view_from_view(
					view, 0, sizeof(*event_rule_comm));

	if (!view || !event_rule) {
		ret = -1;
		goto end;
	}

	if (!lttng_payload_view_is_valid(&event_rule_comm_view)) {
		ret = -1;
		goto end;
	}

	DBG("Deserializing event_rule from payload");
	event_rule_comm = (const struct lttng_event_rule_comm *) event_rule_comm_view.buffer.data;
	consumed += sizeof(*event_rule_comm);

	switch ((enum lttng_event_rule_type) event_rule_comm->event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
		create_from_payload = lttng_event_rule_kernel_kprobe_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
		create_from_payload = lttng_event_rule_kernel_uprobe_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
		create_from_payload =
				lttng_event_rule_kernel_syscall_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		create_from_payload =
				lttng_event_rule_kernel_tracepoint_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		create_from_payload =
				lttng_event_rule_user_tracepoint_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		create_from_payload =
				lttng_event_rule_jul_logging_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		create_from_payload =
				lttng_event_rule_log4j_logging_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		create_from_payload =
				lttng_event_rule_python_logging_create_from_payload;
		break;
	default:
		ERR("Attempted to create event rule of unknown type (%i)",
				(int) event_rule_comm->event_rule_type);
		ret = -1;
		goto end;
	}

	LTTNG_ASSERT(create_from_payload);

	{
		struct lttng_payload_view child_view =
				lttng_payload_view_from_view(
						view, consumed, -1);

		ret = create_from_payload(&child_view, event_rule);
		if (ret < 0) {
			goto end;
		}

		consumed += ret;
	}

	if (!lttng_event_rule_validate(*event_rule)) {
		ret = -1;
		goto end;
	}

	ret = consumed;
end:
	return ret;
}

LTTNG_HIDDEN
void lttng_event_rule_init(struct lttng_event_rule *event_rule,
		enum lttng_event_rule_type type)
{
	urcu_ref_init(&event_rule->ref);
	event_rule->type = type;
}

LTTNG_HIDDEN
bool lttng_event_rule_get(struct lttng_event_rule *event_rule)
{
	return urcu_ref_get_unless_zero(&event_rule->ref);
}

LTTNG_HIDDEN
void lttng_event_rule_put(struct lttng_event_rule *event_rule)
{
	if (!event_rule) {
		return;
	}

	LTTNG_ASSERT(event_rule->ref.refcount);
	urcu_ref_put(&event_rule->ref, lttng_event_rule_release);
}

LTTNG_HIDDEN
enum lttng_error_code lttng_event_rule_generate_filter_bytecode(
		struct lttng_event_rule *rule,
		const struct lttng_credentials *creds)
{
	LTTNG_ASSERT(rule->generate_filter_bytecode);
	return rule->generate_filter_bytecode(rule, creds);
}

LTTNG_HIDDEN
const char *lttng_event_rule_get_filter(const struct lttng_event_rule *rule)
{
	LTTNG_ASSERT(rule->get_filter);
	return rule->get_filter(rule);
}

LTTNG_HIDDEN
const struct lttng_bytecode *lttng_event_rule_get_filter_bytecode(
		const struct lttng_event_rule *rule)
{
	LTTNG_ASSERT(rule->get_filter_bytecode);
	return rule->get_filter_bytecode(rule);
}

LTTNG_HIDDEN
enum lttng_event_rule_generate_exclusions_status
lttng_event_rule_generate_exclusions(const struct lttng_event_rule *rule,
		struct lttng_event_exclusion **exclusions)
{
	LTTNG_ASSERT(rule->generate_exclusions);
	return rule->generate_exclusions(rule, exclusions);
}

LTTNG_HIDDEN
struct lttng_event *lttng_event_rule_generate_lttng_event(
		const struct lttng_event_rule *rule)
{
	LTTNG_ASSERT(rule->generate_lttng_event);
	return rule->generate_lttng_event(rule);
}

LTTNG_HIDDEN
bool lttng_event_rule_targets_agent_domain(const struct lttng_event_rule *rule)
{
	bool targets_agent_domain = false;
	enum lttng_domain_type type = lttng_event_rule_get_domain_type(rule);

	switch (type) {
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
		targets_agent_domain = true;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_KERNEL:
		targets_agent_domain = false;
		break;
	default:
		abort();
	};

	return targets_agent_domain;
}

const char *lttng_event_rule_type_str(enum lttng_event_rule_type type)
{
	switch (type) {
	case LTTNG_EVENT_RULE_TYPE_UNKNOWN:
		return "unknown";
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
		return "kernel syscall";
	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
		return "kernel kprobe";
	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
		return "kernel uprobe";
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		return "kernel tracepoint";
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		return "user tracepoint";
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		return "jul logging";
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		return "log4j logging";
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		return "python logging";

	default:
		abort();
	}
}

LTTNG_HIDDEN
unsigned long lttng_event_rule_hash(const struct lttng_event_rule *rule)
{
	LTTNG_ASSERT(rule->hash);
	return rule->hash(rule);
}

LTTNG_HIDDEN
enum lttng_error_code lttng_event_rule_mi_serialize(
		const struct lttng_event_rule *rule, struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;

	LTTNG_ASSERT(rule);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(rule->mi_serialize);

	/* Open event rule element. */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_event_rule);
	if (ret) {
		goto mi_error;
	}

	/* Serialize underlying event rule. */
	ret_code = rule->mi_serialize(rule, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close event rule element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto mi_error;
	}

	ret_code = LTTNG_OK;
	goto end;

mi_error:
	ret_code = LTTNG_ERR_MI_IO_FAIL;
end:
	return ret_code;
}
