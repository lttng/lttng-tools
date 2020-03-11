/*
 * Copyright (C) 2019 Jonathan Rajotte
 * <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/event-rule/kprobe-internal.h>
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
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
		/* TODO */
		domain_type = LTTNG_DOMAIN_NONE;
		break;
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
	case LTTNG_EVENT_RULE_TYPE_KPROBE:
	case LTTNG_EVENT_RULE_TYPE_KRETPROBE:
	case LTTNG_EVENT_RULE_TYPE_UPROBE:
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

	assert(event_rule->destroy);
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
	const struct lttng_event_rule_comm *event_rule_comm;
	event_rule_create_from_payload_cb create_from_payload = NULL;

	if (!view || !event_rule) {
		ret = -1;
		goto end;
	}

	DBG("Deserializing event_rule from payload.");
	event_rule_comm = (const struct lttng_event_rule_comm *) view->buffer.data;
	consumed += sizeof(*event_rule_comm);

	switch ((enum lttng_event_rule_type) event_rule_comm->event_rule_type) {
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
		/* TODO */
		break;
	case LTTNG_EVENT_RULE_TYPE_KPROBE:
		create_from_payload = lttng_event_rule_kprobe_create_from_payload;
		break;
	case LTTNG_EVENT_RULE_TYPE_KRETPROBE:
		/* TODO */
		break;
	case LTTNG_EVENT_RULE_TYPE_UPROBE:
		/* TODO */
		break;
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
		/* TODO */
		break;
	default:
		ERR("Attempted to create event rule of unknown type (%i)",
				(int) event_rule_comm->event_rule_type);
		ret = -1;
		goto end;
	}

	assert(create_from_payload);

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

	assert(event_rule->ref.refcount);
	urcu_ref_put(&event_rule->ref, lttng_event_rule_release);
}

LTTNG_HIDDEN
enum lttng_error_code lttng_event_rule_generate_filter_bytecode(
		struct lttng_event_rule *rule, uid_t uid, gid_t gid)
{
	assert(rule->generate_filter_bytecode);
	return rule->generate_filter_bytecode(rule, uid, gid);
}

LTTNG_HIDDEN
const char *lttng_event_rule_get_filter(const struct lttng_event_rule *rule)
{
	assert(rule->get_filter);
	return rule->get_filter(rule);
}

LTTNG_HIDDEN
const struct lttng_filter_bytecode *lttng_event_rule_get_filter_bytecode(
		const struct lttng_event_rule *rule)
{
	assert(rule->get_filter_bytecode);
	return rule->get_filter_bytecode(rule);
}

LTTNG_HIDDEN
struct lttng_event_exclusion *lttng_event_rule_generate_exclusions(
		const struct lttng_event_rule *rule)
{
	assert(rule->generate_exclusions);
	return rule->generate_exclusions(rule);
}

LTTNG_HIDDEN
const char *lttng_event_rule_type_str(enum lttng_event_rule_type type)
{
	switch (type) {
	case LTTNG_EVENT_RULE_TYPE_UNKNOWN:
		return "unknown";
	case LTTNG_EVENT_RULE_TYPE_TRACEPOINT:
		return "tracepoint";
	case LTTNG_EVENT_RULE_TYPE_SYSCALL:
		return "syscall";
	case LTTNG_EVENT_RULE_TYPE_KPROBE:
		return "probe";
	case LTTNG_EVENT_RULE_TYPE_KRETPROBE:
		return "function";
	case LTTNG_EVENT_RULE_TYPE_UPROBE:
		return "userspace-probe";
	default:
		abort();
	}
}
