/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/error.h>
#include <common/macros.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/event-rule-internal.h>
#include <lttng/condition/event-rule.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <stdbool.h>

#define IS_EVENT_RULE_CONDITION(condition)      \
	(lttng_condition_get_type(condition) == \
			LTTNG_CONDITION_TYPE_EVENT_RULE_HIT)

static bool is_event_rule_evaluation(const struct lttng_evaluation *evaluation)
{
	enum lttng_condition_type type = lttng_evaluation_get_type(evaluation);

	return type == LTTNG_CONDITION_TYPE_EVENT_RULE_HIT;
}

static bool lttng_condition_event_rule_validate(
		const struct lttng_condition *condition);
static int lttng_condition_event_rule_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload);
static bool lttng_condition_event_rule_is_equal(
		const struct lttng_condition *_a,
		const struct lttng_condition *_b);
static void lttng_condition_event_rule_destroy(
		struct lttng_condition *condition);

static bool lttng_condition_event_rule_validate(
		const struct lttng_condition *condition)
{
	bool valid = false;
	struct lttng_condition_event_rule *event_rule;

	if (!condition) {
		goto end;
	}

	event_rule = container_of(
			condition, struct lttng_condition_event_rule, parent);
	if (!event_rule->rule) {
		ERR("Invalid event rule condition: a rule must be set.");
		goto end;
	}

	valid = lttng_event_rule_validate(event_rule->rule);
end:
	return valid;
}

static int lttng_condition_event_rule_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload)
{
	int ret;
	size_t header_offset, size_before_payload;
	struct lttng_condition_event_rule *event_rule;
	struct lttng_condition_event_rule_comm event_rule_comm = {};
	struct lttng_condition_event_rule_comm *header = NULL;

	if (!condition || !IS_EVENT_RULE_CONDITION(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing event rule condition");
	event_rule = container_of(
			condition, struct lttng_condition_event_rule, parent);

	header_offset = payload->buffer.size;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &event_rule_comm,
			sizeof(event_rule_comm));
	if (ret) {
		goto end;
	}

	size_before_payload = payload->buffer.size;
	ret = lttng_event_rule_serialize(event_rule->rule, payload);
	if (ret) {
		goto end;
	}

	/* Update payload size. */
	header = (struct lttng_condition_event_rule_comm *)
			((char *) payload->buffer.data + header_offset);
	header->event_rule_length = payload->buffer.size - size_before_payload;

end:
	return ret;
}

static bool lttng_condition_event_rule_is_equal(
		const struct lttng_condition *_a,
		const struct lttng_condition *_b)
{
	bool is_equal = false;
	struct lttng_condition_event_rule *a, *b;

	a = container_of(_a, struct lttng_condition_event_rule, parent);
	b = container_of(_b, struct lttng_condition_event_rule, parent);

	/* Both event rules must be set or both must be unset. */
	if ((a->rule && !b->rule) || (!a->rule && b->rule)) {
		WARN("Comparing event_rule conditions with uninitialized rule");
		goto end;
	}

	is_equal = lttng_event_rule_is_equal(a->rule, b->rule);
end:
	return is_equal;
}

static void lttng_condition_event_rule_destroy(
		struct lttng_condition *condition)
{
	struct lttng_condition_event_rule *event_rule;

	event_rule = container_of(
			condition, struct lttng_condition_event_rule, parent);

	lttng_event_rule_put(event_rule->rule);
	free(event_rule);
}

struct lttng_condition *lttng_condition_event_rule_create(
		struct lttng_event_rule *rule)
{
	struct lttng_condition *parent = NULL;
	struct lttng_condition_event_rule *condition = NULL;

	if (!rule) {
		goto end;
	}

	condition = zmalloc(sizeof(struct lttng_condition_event_rule));
	if (!condition) {
		return NULL;
	}

	lttng_condition_init(&condition->parent,
			LTTNG_CONDITION_TYPE_EVENT_RULE_HIT);
	condition->parent.validate = lttng_condition_event_rule_validate,
	condition->parent.serialize = lttng_condition_event_rule_serialize,
	condition->parent.equal = lttng_condition_event_rule_is_equal,
	condition->parent.destroy = lttng_condition_event_rule_destroy,

	lttng_event_rule_get(rule);
	condition->rule = rule;
	rule = NULL;

	parent = &condition->parent;
end:
	return parent;
}

LTTNG_HIDDEN
ssize_t lttng_condition_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **_condition)
{
	ssize_t offset, event_rule_length;
	struct lttng_condition *condition = NULL;
	struct lttng_event_rule *event_rule = NULL;
	const struct lttng_condition_event_rule_comm *header;
	const struct lttng_payload_view header_view =
			lttng_payload_view_from_view(
					view, 0, sizeof(*header));

	if (!view || !_condition) {
		goto error;
	}

	if (!lttng_payload_view_is_valid(&header_view)) {
		ERR("Failed to initialize from malformed event rule condition: buffer too short to contain header");
		goto error;
	}

	header = (const struct lttng_condition_event_rule_comm *)
			       header_view.buffer.data;
	offset = sizeof(*header);

	/* lttng_event_rule payload. */
	{
		struct lttng_payload_view event_rule_view =
				lttng_payload_view_from_view(view, offset, -1);

		event_rule_length = lttng_event_rule_create_from_payload(
				&event_rule_view, &event_rule);
	}

	if (event_rule_length < 0 || !event_rule) {
		goto error;
	}

	if ((size_t) header->event_rule_length != event_rule_length) {
		goto error;
	}

	/* Move to the end of the payload. */
	offset += header->event_rule_length;

	/* Acquires a reference to the event rule. */
	condition = lttng_condition_event_rule_create(event_rule);
	if (!condition) {
		goto error;
	}

	*_condition = condition;
	condition = NULL;
	goto end;

error:
	offset = -1;

end:
	lttng_event_rule_put(event_rule);
	lttng_condition_put(condition);
	return offset;
}

LTTNG_HIDDEN
enum lttng_condition_status lttng_condition_event_rule_borrow_rule_mutable(
		const struct lttng_condition *condition,
		struct lttng_event_rule **rule)
{
	struct lttng_condition_event_rule *event_rule;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_EVENT_RULE_CONDITION(condition) || !rule) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	event_rule = container_of(
			condition, struct lttng_condition_event_rule, parent);
	if (!event_rule->rule) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}

	*rule = event_rule->rule;
end:
	return status;
}

enum lttng_condition_status lttng_condition_event_rule_get_rule(
		const struct lttng_condition *condition,
		const struct lttng_event_rule **rule)
{
	struct lttng_event_rule *mutable_rule = NULL;
	const enum lttng_condition_status status =
			lttng_condition_event_rule_borrow_rule_mutable(
				condition, &mutable_rule);

	*rule = mutable_rule;
	return status;
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret, offset = 0;
	const char *trigger_name;
	struct lttng_evaluation *evaluation = NULL;
	const struct lttng_evaluation_event_rule_comm *header;
	const struct lttng_payload_view header_view =
			lttng_payload_view_from_view(
					view, 0, sizeof(*header));

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	if (!lttng_payload_view_is_valid(&header_view)) {
		ERR("Failed to initialize from malformed event rule evaluation: buffer too short to contain header");
		ret = -1;
		goto error;
	}

	header = (typeof(header)) header_view.buffer.data;

	/* Map the originating trigger's name. */
	offset += sizeof(*header);
	{
		struct lttng_payload_view current_view =
				lttng_payload_view_from_view(view, offset,
						header->trigger_name_length);

		if (!lttng_payload_view_is_valid(&current_view)) {
			ERR("Failed to initialize from malformed event rule evaluation: buffer too short to contain trigger name");
			ret = -1;
			goto error;
		}

		trigger_name = current_view.buffer.data;
		if (!lttng_buffer_view_contains_string(&current_view.buffer,
				    trigger_name, header->trigger_name_length)) {
			ERR("Failed to initialize from malformed event rule evaluation: invalid trigger name");
			ret = -1;
			goto error;
		}
	}

	offset += header->trigger_name_length;

	evaluation = lttng_evaluation_event_rule_create(trigger_name);
	if (!evaluation) {
		ret = -1;
		goto error;
	}

	*_evaluation = evaluation;
	evaluation = NULL;
	ret = offset;

error:
	lttng_evaluation_destroy(evaluation);
	return ret;
}

static int lttng_evaluation_event_rule_serialize(
		const struct lttng_evaluation *evaluation,
		struct lttng_payload *payload)
{
	int ret = 0;
	struct lttng_evaluation_event_rule *hit;
	struct lttng_evaluation_event_rule_comm comm;

	hit = container_of(
			evaluation, struct lttng_evaluation_event_rule, parent);

	assert(hit->name);
	comm.trigger_name_length = strlen(hit->name) + 1;

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, &comm, sizeof(comm));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&payload->buffer, hit->name, comm.trigger_name_length);
end:
	return ret;
}

static void lttng_evaluation_event_rule_destroy(
		struct lttng_evaluation *evaluation)
{
	struct lttng_evaluation_event_rule *hit;

	hit = container_of(
			evaluation, struct lttng_evaluation_event_rule, parent);
	free(hit->name);
	free(hit);
}

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_event_rule_create(
		const char *trigger_name)
{
	struct lttng_evaluation_event_rule *hit;
	struct lttng_evaluation *evaluation = NULL;

	hit = zmalloc(sizeof(struct lttng_evaluation_event_rule));
	if (!hit) {
		goto end;
	}

	hit->name = strdup(trigger_name);
	if (!hit->name) {
		goto end;
	}

	hit->parent.type = LTTNG_CONDITION_TYPE_EVENT_RULE_HIT;
	hit->parent.serialize = lttng_evaluation_event_rule_serialize;
	hit->parent.destroy = lttng_evaluation_event_rule_destroy;

	evaluation = &hit->parent;
	hit = NULL;

end:
	if (hit) {
		lttng_evaluation_event_rule_destroy(&hit->parent);
	}

	return evaluation;
}

enum lttng_evaluation_status lttng_evaluation_event_rule_get_trigger_name(
		const struct lttng_evaluation *evaluation, const char **name)
{
	struct lttng_evaluation_event_rule *hit;
	enum lttng_evaluation_status status = LTTNG_EVALUATION_STATUS_OK;

	if (!evaluation || !is_event_rule_evaluation(evaluation) || !name) {
		status = LTTNG_EVALUATION_STATUS_INVALID;
		goto end;
	}

	hit = container_of(
			evaluation, struct lttng_evaluation_event_rule, parent);
	*name = hit->name;
end:
	return status;
}
