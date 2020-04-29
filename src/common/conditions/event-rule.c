/*
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <common/error.h>
#include <common/macros.h>
#include <inttypes.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/event-rule-internal.h>
#include <lttng/condition/event-rule.h>
#include <lttng/event-expr-internal.h>
#include <lttng/event-expr.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <stdbool.h>
#include <stdint.h>
#include <vendor/msgpack/msgpack.h>

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

/*
 * Serializes the C string `str` into `buf`.
 *
 * Encoding is the length of `str` plus one (for the null character),
 * and then the string, including its null terminator.
 */
static
int serialize_cstr(const char *str, struct lttng_dynamic_buffer *buf)
{
	int ret;
	const uint32_t len = strlen(str) + 1;

	/* Serialize the length, including the null terminator. */
	DBG("Serializing C string's length (including null terminator): "
			"%" PRIu32, len);
	ret = lttng_dynamic_buffer_append(buf, &len, sizeof(len));
	if (ret) {
		goto end;
	}

	/* Serialize the string. */
	DBG("Serializing C string: '%s'", str);
	ret = lttng_dynamic_buffer_append(buf, str, len);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

/*
 * Serializes the event expression `expr` into `buf`.
 */
static
int serialize_event_expr(const struct lttng_event_expr *expr,
		struct lttng_payload *payload)
{
	const uint8_t type = expr->type;
	int ret;

	/* Serialize the expression's type. */
	DBG("Serializing event expression's type: %d", expr->type);
	ret = lttng_dynamic_buffer_append(&payload->buffer, &type, sizeof(type));
	if (ret) {
		goto end;
	}

	/* Serialize the expression */
	switch (expr->type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		const struct lttng_event_expr_field *field_expr =
				container_of(expr,
					const struct lttng_event_expr_field,
					parent);

		/* Serialize the field name. */
		DBG("Serializing field event expression's field name: '%s'",
				field_expr->name);
		ret = serialize_cstr(field_expr->name, &payload->buffer);
		if (ret) {
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		const struct lttng_event_expr_app_specific_context_field *field_expr =
				container_of(expr,
					const struct lttng_event_expr_app_specific_context_field,
					parent);

		/* Serialize the provider name. */
		DBG("Serializing app-specific context field event expression's "
				"provider name: '%s'",
				field_expr->provider_name);
		ret = serialize_cstr(field_expr->provider_name, &payload->buffer);
		if (ret) {
			goto end;
		}

		/* Serialize the type name. */
		DBG("Serializing app-specific context field event expression's "
				"type name: '%s'",
				field_expr->provider_name);
		ret = serialize_cstr(field_expr->type_name, &payload->buffer);
		if (ret) {
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		const struct lttng_event_expr_array_field_element *elem_expr =
				container_of(expr,
					const struct lttng_event_expr_array_field_element,
					parent);
		const uint32_t index = elem_expr->index;

		/* Serialize the index. */
		DBG("Serializing array field element event expression's "
				"index: %u", elem_expr->index);
		ret = lttng_dynamic_buffer_append(&payload->buffer, &index, sizeof(index));
		if (ret) {
			goto end;
		}

		/* Serialize the parent array field expression. */
		DBG("Serializing array field element event expression's "
				"parent array field event expression.");
		ret = serialize_event_expr(elem_expr->array_field_expr, payload);
		if (ret) {
			goto end;
		}

		break;
	}
	default:
		break;
	}

end:
	return ret;
}

static
struct lttng_capture_descriptor *
lttng_condition_event_rule_get_internal_capture_descriptor_at_index(
		const struct lttng_condition *condition, unsigned int index)
{
	const struct lttng_condition_event_rule *event_rule_cond =
			container_of(condition,
				const struct lttng_condition_event_rule,
				parent);
	struct lttng_capture_descriptor *desc = NULL;
	unsigned int count;
	enum lttng_condition_status status;

	if (!condition || !IS_EVENT_RULE_CONDITION(condition)) {
		goto end;
	}

	status = lttng_condition_event_rule_get_capture_descriptor_count(
			condition, &count);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	desc = lttng_dynamic_pointer_array_get_pointer(
			&event_rule_cond->capture_descriptors, index);
end:
	return desc;
}

static int lttng_condition_event_rule_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_condition_event_rule *event_rule;
	enum lttng_condition_status status;
	/* Used for iteration and communication (size matters). */
	uint32_t i, capture_descr_count;

	if (!condition || !IS_EVENT_RULE_CONDITION(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing event rule condition");
	event_rule = container_of(
			condition, struct lttng_condition_event_rule, parent);

	DBG("Serializing event rule condition's event rule");
	ret = lttng_event_rule_serialize(event_rule->rule, payload);
	if (ret) {
		goto end;
	}

	status = lttng_condition_event_rule_get_capture_descriptor_count(
			condition, &capture_descr_count);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ret = -1;
		goto end;
	};

	DBG("Serializing event rule condition's capture descriptor count: %" PRIu32,
			capture_descr_count);
	ret = lttng_dynamic_buffer_append(&payload->buffer, &capture_descr_count,
			sizeof(capture_descr_count));
	if (ret) {
		goto end;
	}

	for (i = 0; i < capture_descr_count; i++) {
		const struct lttng_capture_descriptor *desc =
				lttng_condition_event_rule_get_internal_capture_descriptor_at_index(
						condition, i);

		DBG("Serializing event rule condition's capture descriptor %" PRIu32,
				i);
		ret = serialize_event_expr(desc->event_expression, payload);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static
bool capture_descriptors_are_equal(
		const struct lttng_condition *condition_a,
		const struct lttng_condition *condition_b)
{
	bool is_equal = true;
	unsigned int capture_descr_count_a;
	unsigned int capture_descr_count_b;
	size_t i;
	enum lttng_condition_status status;

	status = lttng_condition_event_rule_get_capture_descriptor_count(
			condition_a, &capture_descr_count_a);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto not_equal;
	}

	status = lttng_condition_event_rule_get_capture_descriptor_count(
			condition_b, &capture_descr_count_b);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto not_equal;
	}

	if (capture_descr_count_a != capture_descr_count_b) {
		goto not_equal;
	}

	for (i = 0; i < capture_descr_count_a; i++) {
		const struct lttng_event_expr *expr_a =
				lttng_condition_event_rule_get_capture_descriptor_at_index(
					condition_a,
					i);
		const struct lttng_event_expr *expr_b =
				lttng_condition_event_rule_get_capture_descriptor_at_index(
					condition_b,
					i);

		if (!lttng_event_expr_is_equal(expr_a, expr_b)) {
			goto not_equal;
		}
	}

	goto end;

not_equal:
	is_equal = false;

end:
	return is_equal;
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
	if (!is_equal) {
		goto end;
	}

	is_equal = capture_descriptors_are_equal(_a, _b);

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
	lttng_dynamic_pointer_array_reset(&event_rule->capture_descriptors);
	free(event_rule);
}

static
void destroy_capture_descriptor(void *ptr)
{
	struct lttng_capture_descriptor *desc =
			(struct lttng_capture_descriptor *) ptr;

	lttng_event_expr_destroy(desc->event_expression);
	free(desc->bytecode);
	free(desc);
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

	lttng_dynamic_pointer_array_init(&condition->capture_descriptors,
			destroy_capture_descriptor);

	parent = &condition->parent;
end:
	return parent;
}

static
uint64_t uint_from_buffer(const struct lttng_buffer_view *view, size_t size,
		size_t *offset)
{
	uint64_t ret;
	const struct lttng_buffer_view uint_view =
			lttng_buffer_view_from_view(view, *offset, size);

	if (!lttng_buffer_view_is_valid(&uint_view)) {
		ret = UINT64_C(-1);
		goto end;
	}

	switch (size) {
	case 1:
		ret = (uint64_t) *uint_view.data;
		break;
	case sizeof(uint32_t):
	{
		uint32_t u32;

		memcpy(&u32, uint_view.data, sizeof(u32));
		ret = (uint64_t) u32;
		break;
	}
	case sizeof(ret):
		memcpy(&ret, uint_view.data, sizeof(ret));
		break;
	default:
		abort();
	}

	*offset += size;

end:
	return ret;
}

static
const char *str_from_buffer(const struct lttng_buffer_view *view,
		size_t *offset)
{
	uint64_t len;
	const char *ret;

	len = uint_from_buffer(view, sizeof(uint32_t), offset);
	if (len == UINT64_C(-1)) {
		goto error;
	}

	ret = &view->data[*offset];

	if (!lttng_buffer_view_contains_string(view, ret, len)) {
		goto error;
	}

	*offset += len;
	goto end;

error:
	ret = NULL;

end:
	return ret;
}

static
struct lttng_event_expr *event_expr_from_payload(
		struct lttng_payload_view *view, size_t *offset)
{
	struct lttng_event_expr *expr = NULL;
	const char *str;
	uint64_t type;

	type = uint_from_buffer(&view->buffer, sizeof(uint8_t), offset);
	if (type == UINT64_C(-1)) {
		goto error;
	}

	switch (type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
		str = str_from_buffer(&view->buffer, offset);
		if (!str) {
			goto error;
		}

		expr = lttng_event_expr_event_payload_field_create(str);
		break;
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
		str = str_from_buffer(&view->buffer, offset);
		if (!str) {
			goto error;
		}

		expr = lttng_event_expr_channel_context_field_create(str);
		break;
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		const char *provider_name;
		const char *type_name;

		provider_name = str_from_buffer(&view->buffer, offset);
		if (!provider_name) {
			goto error;
		}

		type_name = str_from_buffer(&view->buffer, offset);
		if (!type_name) {
			goto error;
		}

		expr = lttng_event_expr_app_specific_context_field_create(
				provider_name, type_name);
		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		struct lttng_event_expr *array_field_expr;
		const uint64_t index = uint_from_buffer(
				&view->buffer, sizeof(uint32_t), offset);

		if (index == UINT64_C(-1)) {
			goto error;
		}

		/* Array field expression is the encoded after this. */
		array_field_expr = event_expr_from_payload(view, offset);
		if (!array_field_expr) {
			goto error;
		}

		/* Move ownership of `array_field_expr` to new expression. */
		expr = lttng_event_expr_array_field_element_create(
				array_field_expr, (unsigned int) index);
		if (!expr) {
			/* `array_field_expr` not moved: destroy it. */
			lttng_event_expr_destroy(array_field_expr);
		}

		break;
	}
	default:
		abort();
	}

	goto end;

error:
	lttng_event_expr_destroy(expr);
	expr = NULL;

end:
	return expr;
}

LTTNG_HIDDEN
ssize_t lttng_condition_event_rule_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_condition **_condition)
{
	ssize_t consumed_length;
	size_t offset = 0;
	ssize_t event_rule_length;
	uint32_t i, capture_descr_count;
	struct lttng_condition *condition = NULL;
	struct lttng_event_rule *event_rule = NULL;

	if (!view || !_condition) {
		goto error;
	}

	/* Struct lttng_event_rule. */
	{
		struct lttng_payload_view event_rule_view =
				lttng_payload_view_from_view(view, offset, -1);

		event_rule_length = lttng_event_rule_create_from_payload(
				&event_rule_view, &event_rule);
	}

	if (event_rule_length < 0 || !event_rule) {
		goto error;
	}

	/* Create condition (no capture descriptors yet) at this point. */
	condition = lttng_condition_event_rule_create(event_rule);
	if (!condition) {
		goto error;
	}


	/* Capture descriptor count. */
	assert(event_rule_length >= 0);
	offset += (size_t) event_rule_length;
	capture_descr_count = uint_from_buffer(&view->buffer, sizeof(uint32_t), &offset);
	if (capture_descr_count == UINT32_C(-1)) {
		goto error;
	}

	/* Capture descriptors. */
	for (i = 0; i < capture_descr_count; i++) {
		enum lttng_condition_status status;
		struct lttng_event_expr *expr = event_expr_from_payload(
				view, &offset);

		if (!expr) {
			goto error;
		}

		/* Move ownership of `expr` to `condition`. */
		status = lttng_condition_event_rule_append_capture_descriptor(
				condition, expr);
		if (status != LTTNG_CONDITION_STATUS_OK) {
			/* `expr` not moved: destroy it. */
			lttng_event_expr_destroy(expr);
			goto error;
		}
	}

	consumed_length = (ssize_t) offset;
	*_condition = condition;
	condition = NULL;
	goto end;

error:
	consumed_length = -1;

end:
	lttng_event_rule_put(event_rule);
	lttng_condition_put(condition);
	return consumed_length;
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

enum lttng_condition_status
lttng_condition_event_rule_append_capture_descriptor(
		struct lttng_condition *condition,
		struct lttng_event_expr *expr)
{
	int ret;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;
	struct lttng_condition_event_rule *event_rule_cond =
			container_of(condition,
				struct lttng_condition_event_rule, parent);
	struct lttng_capture_descriptor *descriptor = NULL;

	/* Only accept l-values. */
	if (!condition || !IS_EVENT_RULE_CONDITION(condition) || !expr ||
			!lttng_event_expr_is_lvalue(expr)) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	descriptor = malloc(sizeof(*descriptor));
	if (descriptor == NULL) {
		status = LTTNG_CONDITION_STATUS_ERROR;
		goto end;
	}

	descriptor->event_expression = expr;
	descriptor->bytecode = NULL;

	ret = lttng_dynamic_pointer_array_add_pointer(
			&event_rule_cond->capture_descriptors, descriptor);
	if (ret) {
		status = LTTNG_CONDITION_STATUS_ERROR;
		goto end;
	}

	/* Ownership is transfered to the internal capture_descriptors array */
	descriptor = NULL;
end:
	free(descriptor);
	return status;
}

enum lttng_condition_status
lttng_condition_event_rule_get_capture_descriptor_count(
		const struct lttng_condition *condition, unsigned int *count)
{
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;
	const struct lttng_condition_event_rule *event_rule_cond =
			container_of(condition,
				const struct lttng_condition_event_rule,
				parent);

	if (!condition || !IS_EVENT_RULE_CONDITION(condition) || !count) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(
			&event_rule_cond->capture_descriptors);

end:
	return status;
}

const struct lttng_event_expr *
lttng_condition_event_rule_get_capture_descriptor_at_index(
		const struct lttng_condition *condition, unsigned int index)
{
	const struct lttng_event_expr *expr = NULL;
	const struct lttng_capture_descriptor *desc = NULL;

	desc = lttng_condition_event_rule_get_internal_capture_descriptor_at_index(
			condition, index);
	if (desc == NULL) {
		goto end;
	}
	expr = desc->event_expression;

end:
	return expr;
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
