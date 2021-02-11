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
#include <limits.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/event-rule-matches-internal.h>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/event-expr-internal.h>
#include <lttng/event-expr.h>
#include <lttng/event-field-value-internal.h>
#include <lttng/event-rule/event-rule-internal.h>
#include <lttng/lttng-error.h>
#include <stdbool.h>
#include <stdint.h>
#include <vendor/msgpack/msgpack.h>

#define IS_EVENT_RULE_MATCHES_CONDITION(condition) \
	(lttng_condition_get_type(condition) ==    \
			LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES)

static bool is_event_rule_matches_evaluation(
		const struct lttng_evaluation *evaluation)
{
	enum lttng_condition_type type = lttng_evaluation_get_type(evaluation);

	return type == LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES;
}

static bool lttng_condition_event_rule_matches_validate(
		const struct lttng_condition *condition);
static int lttng_condition_event_rule_matches_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload);
static bool lttng_condition_event_rule_matches_is_equal(
		const struct lttng_condition *_a,
		const struct lttng_condition *_b);
static void lttng_condition_event_rule_matches_destroy(
		struct lttng_condition *condition);

static bool lttng_condition_event_rule_matches_validate(
		const struct lttng_condition *condition)
{
	bool valid = false;
	struct lttng_condition_event_rule_matches *event_rule;

	if (!condition) {
		goto end;
	}

	event_rule = container_of(condition,
			struct lttng_condition_event_rule_matches, parent);
	if (!event_rule->rule) {
		ERR("Invalid on event condition: a rule must be set");
		goto end;
	}

	valid = lttng_event_rule_validate(event_rule->rule);
end:
	return valid;
}

static const char *msgpack_object_type_str(msgpack_object_type type)
{
	const char *name;

	switch (type) {
	case MSGPACK_OBJECT_NIL:
		name = "MSGPACK_OBJECT_NIL";
		break;
	case MSGPACK_OBJECT_BOOLEAN:
		name = "MSGPACK_OBJECT_BOOLEAN";
		break;
	case MSGPACK_OBJECT_POSITIVE_INTEGER:
		name = "MSGPACK_OBJECT_POSITIVE_INTEGER";
		break;
	case MSGPACK_OBJECT_NEGATIVE_INTEGER:
		name = "MSGPACK_OBJECT_NEGATIVE_INTEGER";
		break;
	case MSGPACK_OBJECT_FLOAT32:
		name = "MSGPACK_OBJECT_FLOAT32";
		break;
	case MSGPACK_OBJECT_FLOAT:
		/* Same value as MSGPACK_OBJECT_FLOAT64 */
		name = "MSGPACK_OBJECT_FLOAT(64)";
		break;
	case MSGPACK_OBJECT_STR:
		name = "MSGPACK_OBJECT_STR";
		break;
	case MSGPACK_OBJECT_ARRAY:
		name = "MSGPACK_OBJECT_ARRAY";
		break;
	case MSGPACK_OBJECT_MAP:
		name = "MSGPACK_OBJECT_MAP";
		break;
	case MSGPACK_OBJECT_BIN:
		name = "MSGPACK_OBJECT_BIN";
		break;
	case MSGPACK_OBJECT_EXT:
		name = "MSGPACK_OBJECT_EXT";
		break;
	default:
		abort();
	}

	return name;
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
				"parent array field event expression");
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

static struct lttng_capture_descriptor *
lttng_condition_event_rule_matches_get_internal_capture_descriptor_at_index(
		const struct lttng_condition *condition, unsigned int index)
{
	const struct lttng_condition_event_rule_matches
			*event_rule_matches_cond = container_of(condition,
					const struct lttng_condition_event_rule_matches,
					parent);
	struct lttng_capture_descriptor *desc = NULL;
	unsigned int count;
	enum lttng_condition_status status;

	if (!condition || !IS_EVENT_RULE_MATCHES_CONDITION(condition)) {
		goto end;
	}

	status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
			condition, &count);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	desc = lttng_dynamic_pointer_array_get_pointer(
			&event_rule_matches_cond->capture_descriptors, index);
end:
	return desc;
}

static int lttng_condition_event_rule_matches_serialize(
		const struct lttng_condition *condition,
		struct lttng_payload *payload)
{
	int ret;
	struct lttng_condition_event_rule_matches *event_rule_matches_condition;
	enum lttng_condition_status status;
	/* Used for iteration and communication (size matters). */
	uint32_t i, capture_descr_count;

	if (!condition || !IS_EVENT_RULE_MATCHES_CONDITION(condition)) {
		ret = -1;
		goto end;
	}

	DBG("Serializing on event condition");
	event_rule_matches_condition = container_of(condition,
			struct lttng_condition_event_rule_matches, parent);

	DBG("Serializing on event condition's event rule");
	ret = lttng_event_rule_serialize(
			event_rule_matches_condition->rule, payload);
	if (ret) {
		goto end;
	}

	status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
			condition, &capture_descr_count);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ret = -1;
		goto end;
	};

	DBG("Serializing on event condition's capture descriptor count: %" PRIu32,
			capture_descr_count);
	ret = lttng_dynamic_buffer_append(&payload->buffer, &capture_descr_count,
			sizeof(capture_descr_count));
	if (ret) {
		goto end;
	}

	for (i = 0; i < capture_descr_count; i++) {
		const struct lttng_capture_descriptor *desc =
				lttng_condition_event_rule_matches_get_internal_capture_descriptor_at_index(
						condition, i);

		DBG("Serializing on event condition's capture descriptor %" PRIu32,
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

	status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
			condition_a, &capture_descr_count_a);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto not_equal;
	}

	status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
			condition_b, &capture_descr_count_b);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto not_equal;
	}

	if (capture_descr_count_a != capture_descr_count_b) {
		goto not_equal;
	}

	for (i = 0; i < capture_descr_count_a; i++) {
		const struct lttng_event_expr *expr_a =
				lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
						condition_a, i);
		const struct lttng_event_expr *expr_b =
				lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
						condition_b, i);

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

static bool lttng_condition_event_rule_matches_is_equal(
		const struct lttng_condition *_a,
		const struct lttng_condition *_b)
{
	bool is_equal = false;
	struct lttng_condition_event_rule_matches *a, *b;

	a = container_of(_a, struct lttng_condition_event_rule_matches, parent);
	b = container_of(_b, struct lttng_condition_event_rule_matches, parent);

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

static void lttng_condition_event_rule_matches_destroy(
		struct lttng_condition *condition)
{
	struct lttng_condition_event_rule_matches *event_rule_matches_condition;

	event_rule_matches_condition = container_of(condition,
			struct lttng_condition_event_rule_matches, parent);

	lttng_event_rule_put(event_rule_matches_condition->rule);
	lttng_dynamic_pointer_array_reset(
			&event_rule_matches_condition->capture_descriptors);
	free(event_rule_matches_condition);
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

struct lttng_condition *lttng_condition_event_rule_matches_create(
		struct lttng_event_rule *rule)
{
	struct lttng_condition *parent = NULL;
	struct lttng_condition_event_rule_matches *condition = NULL;

	if (!rule) {
		goto end;
	}

	condition = zmalloc(sizeof(struct lttng_condition_event_rule_matches));
	if (!condition) {
		return NULL;
	}

	lttng_condition_init(&condition->parent,
			LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);
	condition->parent.validate =
			lttng_condition_event_rule_matches_validate,
	condition->parent.serialize =
			lttng_condition_event_rule_matches_serialize,
	condition->parent.equal = lttng_condition_event_rule_matches_is_equal,
	condition->parent.destroy = lttng_condition_event_rule_matches_destroy,

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
		ERR("Invalid event expression type encoutered while deserializing event expression: type = %" PRIu64,
				type);
		goto error;
	}

	goto end;

error:
	lttng_event_expr_destroy(expr);
	expr = NULL;

end:
	return expr;
}

LTTNG_HIDDEN
ssize_t lttng_condition_event_rule_matches_create_from_payload(
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

	offset += event_rule_length;

	/* Create condition (no capture descriptors yet) at this point */
	condition = lttng_condition_event_rule_matches_create(event_rule);
	if (!condition) {
		goto error;
	}

	/* Capture descriptor count. */
	assert(event_rule_length >= 0);
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
		status = lttng_condition_event_rule_matches_append_capture_descriptor(
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
enum lttng_condition_status
lttng_condition_event_rule_matches_borrow_rule_mutable(
		const struct lttng_condition *condition,
		struct lttng_event_rule **rule)
{
	struct lttng_condition_event_rule_matches *event_rule;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;

	if (!condition || !IS_EVENT_RULE_MATCHES_CONDITION(condition) ||
			!rule) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	event_rule = container_of(condition,
			struct lttng_condition_event_rule_matches, parent);
	if (!event_rule->rule) {
		status = LTTNG_CONDITION_STATUS_UNSET;
		goto end;
	}

	*rule = event_rule->rule;
end:
	return status;
}

enum lttng_condition_status lttng_condition_event_rule_matches_get_rule(
		const struct lttng_condition *condition,
		const struct lttng_event_rule **rule)
{
	struct lttng_event_rule *mutable_rule = NULL;
	const enum lttng_condition_status status =
			lttng_condition_event_rule_matches_borrow_rule_mutable(
					condition, &mutable_rule);

	*rule = mutable_rule;
	return status;
}

LTTNG_HIDDEN
void lttng_condition_event_rule_matches_set_error_counter_index(
		struct lttng_condition *condition, uint64_t error_counter_index)
{
	struct lttng_condition_event_rule_matches *event_rule_matches_cond =
			container_of(condition,
					struct lttng_condition_event_rule_matches,
					parent);

	LTTNG_OPTIONAL_SET(&event_rule_matches_cond->error_counter_index,
			error_counter_index);
}

LTTNG_HIDDEN
uint64_t lttng_condition_event_rule_matches_get_error_counter_index(
		const struct lttng_condition *condition)
{
	const struct lttng_condition_event_rule_matches
			*event_rule_matches_cond = container_of(condition,
					const struct lttng_condition_event_rule_matches,
					parent);

	return LTTNG_OPTIONAL_GET(event_rule_matches_cond->error_counter_index);
}

enum lttng_condition_status
lttng_condition_event_rule_matches_append_capture_descriptor(
		struct lttng_condition *condition,
		struct lttng_event_expr *expr)
{
	int ret;
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;
	struct lttng_condition_event_rule_matches *event_rule_matches_cond =
			container_of(condition,
					struct lttng_condition_event_rule_matches,
					parent);
	struct lttng_capture_descriptor *descriptor = NULL;
	const struct lttng_event_rule *rule = NULL;

	/* Only accept l-values. */
	if (!condition || !IS_EVENT_RULE_MATCHES_CONDITION(condition) ||
			!expr || !lttng_event_expr_is_lvalue(expr)) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	status = lttng_condition_event_rule_matches_get_rule(condition, &rule);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto end;
	}

	switch(lttng_event_rule_get_type(rule)) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
		/* Supported. */
		status = LTTNG_CONDITION_STATUS_OK;
		break;
	case LTTNG_EVENT_RULE_TYPE_UNKNOWN:
		status = LTTNG_CONDITION_STATUS_INVALID;
		break;
	default:
		status = LTTNG_CONDITION_STATUS_UNSUPPORTED;
		break;
	}

	if (status != LTTNG_CONDITION_STATUS_OK) {
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
			&event_rule_matches_cond->capture_descriptors,
			descriptor);
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
lttng_condition_event_rule_matches_get_capture_descriptor_count(
		const struct lttng_condition *condition, unsigned int *count)
{
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;
	const struct lttng_condition_event_rule_matches
			*event_rule_matches_condition = container_of(condition,
					const struct lttng_condition_event_rule_matches,
					parent);

	if (!condition || !IS_EVENT_RULE_MATCHES_CONDITION(condition) ||
			!count) {
		status = LTTNG_CONDITION_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(
			&event_rule_matches_condition->capture_descriptors);

end:
	return status;
}

const struct lttng_event_expr *
lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
		const struct lttng_condition *condition, unsigned int index)
{
	const struct lttng_event_expr *expr = NULL;
	const struct lttng_capture_descriptor *desc = NULL;

	desc = lttng_condition_event_rule_matches_get_internal_capture_descriptor_at_index(
			condition, index);
	if (desc == NULL) {
		goto end;
	}
	expr = desc->event_expression;

end:
	return expr;
}

LTTNG_HIDDEN
ssize_t lttng_evaluation_event_rule_matches_create_from_payload(
		const struct lttng_condition_event_rule_matches *condition,
		struct lttng_payload_view *view,
		struct lttng_evaluation **_evaluation)
{
	ssize_t ret, offset = 0;
	struct lttng_evaluation *evaluation = NULL;
	uint32_t capture_payload_size;
	const char *capture_payload = NULL;

	if (!_evaluation) {
		ret = -1;
		goto error;
	}

	{
		const struct lttng_payload_view current_view =
				lttng_payload_view_from_view(view, offset, -1);

		if (current_view.buffer.size < sizeof(capture_payload_size)) {
			ret = -1;
			goto error;
		}

		memcpy(&capture_payload_size, current_view.buffer.data,
				sizeof(capture_payload_size));
	}
	offset += sizeof(capture_payload_size);

	if (capture_payload_size > 0) {
		const struct lttng_payload_view current_view =
				lttng_payload_view_from_view(view, offset, -1);

		if (current_view.buffer.size < capture_payload_size) {
			ret = -1;
			goto error;
		}

		capture_payload = current_view.buffer.data;
	}

	evaluation = lttng_evaluation_event_rule_matches_create(
			condition, capture_payload, capture_payload_size, true);
	if (!evaluation) {
		ret = -1;
		goto error;
	}

	offset += capture_payload_size;
	*_evaluation = evaluation;
	evaluation = NULL;
	ret = offset;

error:
	lttng_evaluation_destroy(evaluation);
	return ret;
}

static int lttng_evaluation_event_rule_matches_serialize(
		const struct lttng_evaluation *evaluation,
		struct lttng_payload *payload)
{
	int ret = 0;
	struct lttng_evaluation_event_rule_matches *hit;
	uint32_t capture_payload_size;

	hit = container_of(evaluation,
			struct lttng_evaluation_event_rule_matches, parent);

	capture_payload_size = (uint32_t) hit->capture_payload.size;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &capture_payload_size,
			sizeof(capture_payload_size));
	if (ret) {
		goto end;
	}

	ret = lttng_dynamic_buffer_append(&payload->buffer, hit->capture_payload.data,
			hit->capture_payload.size);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

static
bool msgpack_str_is_equal(const struct msgpack_object *obj, const char *str)
{
	bool is_equal = true;

	assert(obj->type == MSGPACK_OBJECT_STR);

	if (obj->via.str.size != strlen(str)) {
		is_equal = false;
		goto end;
	}

	if (strncmp(obj->via.str.ptr, str, obj->via.str.size) != 0) {
		is_equal = false;
		goto end;
	}

end:
	return is_equal;
}

static
const msgpack_object *get_msgpack_map_obj(const struct msgpack_object *map_obj,
		const char *name)
{
	const msgpack_object *ret = NULL;
	size_t i;

	assert(map_obj->type == MSGPACK_OBJECT_MAP);

	for (i = 0; i < map_obj->via.map.size; i++) {
		const struct msgpack_object_kv *kv = &map_obj->via.map.ptr[i];

		assert(kv->key.type == MSGPACK_OBJECT_STR);

		if (msgpack_str_is_equal(&kv->key, name)) {
			ret = &kv->val;
			goto end;
		}
	}

end:
	return ret;
}

static void lttng_evaluation_event_rule_matches_destroy(
		struct lttng_evaluation *evaluation)
{
	struct lttng_evaluation_event_rule_matches *hit;

	hit = container_of(evaluation,
			struct lttng_evaluation_event_rule_matches, parent);
	lttng_dynamic_buffer_reset(&hit->capture_payload);
	lttng_event_field_value_destroy(hit->captured_values);
	free(hit);
}

static
int event_field_value_from_obj(const msgpack_object *obj,
		struct lttng_event_field_value **field_val)
{
	int ret = 0;

	assert(obj);
	assert(field_val);

	switch (obj->type) {
	case MSGPACK_OBJECT_NIL:
		/* Unavailable. */
		*field_val = NULL;
		goto end;
	case MSGPACK_OBJECT_POSITIVE_INTEGER:
		*field_val = lttng_event_field_value_uint_create(
				obj->via.u64);
		break;
	case MSGPACK_OBJECT_NEGATIVE_INTEGER:
		*field_val = lttng_event_field_value_int_create(
				obj->via.i64);
		break;
	case MSGPACK_OBJECT_FLOAT32:
	case MSGPACK_OBJECT_FLOAT64:
		*field_val = lttng_event_field_value_real_create(
				obj->via.f64);
		break;
	case MSGPACK_OBJECT_STR:
		*field_val = lttng_event_field_value_string_create_with_size(
				obj->via.str.ptr, obj->via.str.size);
		break;
	case MSGPACK_OBJECT_ARRAY:
	{
		size_t i;

		*field_val = lttng_event_field_value_array_create();
		if (!*field_val) {
			goto error;
		}

		for (i = 0; i < obj->via.array.size; i++) {
			const msgpack_object *elem_obj = &obj->via.array.ptr[i];
			struct lttng_event_field_value *elem_field_val;

			ret = event_field_value_from_obj(elem_obj,
					&elem_field_val);
			if (ret) {
				goto error;
			}

			if (elem_field_val) {
				ret = lttng_event_field_value_array_append(
						*field_val, elem_field_val);
			} else {
				ret = lttng_event_field_value_array_append_unavailable(
						*field_val);
			}

			if (ret) {
				lttng_event_field_value_destroy(elem_field_val);
				goto error;
			}
		}

		break;
	}
	case MSGPACK_OBJECT_MAP:
	{
		/*
		 * As of this version, the only valid map object is
		 * for an enumeration value, for example:
		 *
		 *     type: enum
		 *     value: 177
		 *     labels:
		 *     - Labatt 50
		 *     - Molson Dry
		 *     - Carling Black Label
		 */
		const msgpack_object *inner_obj;
		size_t label_i;

		inner_obj = get_msgpack_map_obj(obj, "type");
		if (!inner_obj) {
			ERR("Missing `type` entry in map object");
			goto error;
		}

		if (inner_obj->type != MSGPACK_OBJECT_STR) {
			ERR("Map object's `type` entry is not a string: type = %s",
					msgpack_object_type_str(inner_obj->type));
			goto error;
		}

		if (!msgpack_str_is_equal(inner_obj, "enum")) {
			ERR("Map object's `type` entry: expecting `enum`");
			goto error;
		}

		inner_obj = get_msgpack_map_obj(obj, "value");
		if (!inner_obj) {
			ERR("Missing `value` entry in map object");
			goto error;
		}

		if (inner_obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
			*field_val = lttng_event_field_value_enum_uint_create(
					inner_obj->via.u64);
		} else if (inner_obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
			*field_val = lttng_event_field_value_enum_int_create(
					inner_obj->via.i64);
		} else {
			ERR("Map object's `value` entry is not an integer: type = %s",
					msgpack_object_type_str(inner_obj->type));
			goto error;
		}

		if (!*field_val) {
			goto error;
		}

		inner_obj = get_msgpack_map_obj(obj, "labels");
		if (!inner_obj) {
			/* No labels */
			goto end;
		}

		if (inner_obj->type != MSGPACK_OBJECT_ARRAY) {
			ERR("Map object's `labels` entry is not an array: type = %s",
					msgpack_object_type_str(inner_obj->type));
			goto error;
		}

		for (label_i = 0; label_i < inner_obj->via.array.size;
				label_i++) {
			int iret;
			const msgpack_object *elem_obj =
					&inner_obj->via.array.ptr[label_i];

			if (elem_obj->type != MSGPACK_OBJECT_STR) {
				ERR("Map object's `labels` entry's type is not a string: type = %s",
						msgpack_object_type_str(elem_obj->type));
				goto error;
			}

			iret = lttng_event_field_value_enum_append_label_with_size(
					*field_val, elem_obj->via.str.ptr,
					elem_obj->via.str.size);
			if (iret) {
				goto error;
			}
		}

		break;
	}
	default:
		ERR("Unexpected object type: type = %s",
				msgpack_object_type_str(obj->type));
		goto error;
	}

	if (!*field_val) {
		goto error;
	}

	goto end;

error:
	lttng_event_field_value_destroy(*field_val);
	*field_val = NULL;
	ret = -1;

end:
	return ret;
}

static struct lttng_event_field_value *event_field_value_from_capture_payload(
		const struct lttng_condition_event_rule_matches *condition,
		const char *capture_payload,
		size_t capture_payload_size)
{
	struct lttng_event_field_value *ret = NULL;
	msgpack_unpacked unpacked;
	msgpack_unpack_return unpack_return;
	const msgpack_object *root_obj;
	const msgpack_object_array *root_array_obj;
	size_t i;
	size_t count;

	assert(condition);
	assert(capture_payload);

	/* Initialize value. */
	msgpack_unpacked_init(&unpacked);

	/* Decode. */
	unpack_return = msgpack_unpack_next(&unpacked, capture_payload,
			capture_payload_size, NULL);
	if (unpack_return != MSGPACK_UNPACK_SUCCESS) {
		ERR("msgpack_unpack_next() failed to decode the "
				"MessagePack-encoded capture payload: "
				"size = %zu, ret = %d",
				capture_payload_size, unpack_return);
		goto error;
	}

	/* Get root array. */
	root_obj = &unpacked.data;

	if (root_obj->type != MSGPACK_OBJECT_ARRAY) {
		ERR("Expecting an array as the root object: type = %s",
				msgpack_object_type_str(root_obj->type));
		goto error;
	}

	root_array_obj = &root_obj->via.array;

	/* Create an empty root array event field value. */
	ret = lttng_event_field_value_array_create();
	if (!ret) {
		goto error;
	}

	/*
	 * For each capture descriptor in the condition object:
	 *
	 * 1. Get its corresponding captured field value MessagePack
	 *    object.
	 *
	 * 2. Create a corresponding event field value.
	 *
	 * 3. Append it to `ret` (the root array event field value).
	 */
	count = lttng_dynamic_pointer_array_get_count(
			&condition->capture_descriptors);
	assert(count > 0);

	for (i = 0; i < count; i++) {
		const struct lttng_capture_descriptor *capture_descriptor =
				lttng_condition_event_rule_matches_get_internal_capture_descriptor_at_index(
						&condition->parent, i);
		const msgpack_object *elem_obj;
		struct lttng_event_field_value *elem_field_val;
		int iret;

		assert(capture_descriptor);

		elem_obj = &root_array_obj->ptr[i];
		iret = event_field_value_from_obj(elem_obj,
				&elem_field_val);
		if (iret) {
			goto error;
		}

		if (elem_field_val) {
			iret = lttng_event_field_value_array_append(ret,
					elem_field_val);
		} else {
			iret = lttng_event_field_value_array_append_unavailable(
					ret);
		}

		if (iret) {
			lttng_event_field_value_destroy(elem_field_val);
			goto error;
		}
	}

	goto end;

error:
	lttng_event_field_value_destroy(ret);
	ret = NULL;

end:
	msgpack_unpacked_destroy(&unpacked);
	return ret;
}

LTTNG_HIDDEN
struct lttng_evaluation *lttng_evaluation_event_rule_matches_create(
		const struct lttng_condition_event_rule_matches *condition,
		const char *capture_payload,
		size_t capture_payload_size,
		bool decode_capture_payload)
{
	struct lttng_evaluation_event_rule_matches *hit;
	struct lttng_evaluation *evaluation = NULL;

	hit = zmalloc(sizeof(struct lttng_evaluation_event_rule_matches));
	if (!hit) {
		goto error;
	}

	lttng_dynamic_buffer_init(&hit->capture_payload);

	if (capture_payload) {
		const int ret = lttng_dynamic_buffer_append(
				&hit->capture_payload, capture_payload,
				capture_payload_size);
		if (ret) {
			ERR("Failed to initialize capture payload of event rule evaluation");
			goto error;
		}

		if (decode_capture_payload) {
			hit->captured_values =
					event_field_value_from_capture_payload(
						condition,
						capture_payload,
						capture_payload_size);
			if (!hit->captured_values) {
				ERR("Failed to decode the capture payload: size = %zu",
						capture_payload_size);
				goto error;
			}
		}
	}

	hit->parent.type = LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES;
	hit->parent.serialize = lttng_evaluation_event_rule_matches_serialize;
	hit->parent.destroy = lttng_evaluation_event_rule_matches_destroy;

	evaluation = &hit->parent;
	hit = NULL;

error:
	if (hit) {
		lttng_evaluation_event_rule_matches_destroy(&hit->parent);
	}

	return evaluation;
}

enum lttng_evaluation_event_rule_matches_status
lttng_evaluation_event_rule_matches_get_captured_values(
		const struct lttng_evaluation *evaluation,
		const struct lttng_event_field_value **field_val)
{
	struct lttng_evaluation_event_rule_matches *hit;
	enum lttng_evaluation_event_rule_matches_status status =
			LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_OK;

	if (!evaluation || !is_event_rule_matches_evaluation(evaluation) ||
			!field_val) {
		status = LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_INVALID;
		goto end;
	}

	hit = container_of(evaluation,
			struct lttng_evaluation_event_rule_matches, parent);
	if (!hit->captured_values) {
		status = LTTNG_EVALUATION_EVENT_RULE_MATCHES_STATUS_NONE;
		goto end;
	}

	*field_val = hit->captured_values;

end:
	return status;
}

LTTNG_HIDDEN
enum lttng_error_code
lttng_condition_event_rule_matches_generate_capture_descriptor_bytecode(
		struct lttng_condition *condition)
{
	enum lttng_error_code ret;
	enum lttng_condition_status status;
	unsigned int capture_count, i;

	if (!condition || !IS_EVENT_RULE_MATCHES_CONDITION(condition)) {
		ret = LTTNG_ERR_FATAL;
		goto end;
	}

	status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
			condition, &capture_count);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ret = LTTNG_ERR_FATAL;
		goto end;
	}

	for (i = 0; i < capture_count; i++) {
		struct lttng_capture_descriptor *local_capture_desc =
				lttng_condition_event_rule_matches_get_internal_capture_descriptor_at_index(
						condition, i);

		if (local_capture_desc == NULL) {
			ret = LTTNG_ERR_FATAL;
			goto end;
		}

		/* Generate the bytecode. */
		status = lttng_event_expr_to_bytecode(
				local_capture_desc->event_expression,
				&local_capture_desc->bytecode);
		if (status < 0 || local_capture_desc->bytecode == NULL) {
			ret = LTTNG_ERR_INVALID_CAPTURE_EXPRESSION;
			goto end;
		}
	}

	/* Everything went better than expected */
	ret = LTTNG_OK;

end:
	return ret;
}

LTTNG_HIDDEN
const struct lttng_bytecode *
lttng_condition_event_rule_matches_get_capture_bytecode_at_index(
		const struct lttng_condition *condition, unsigned int index)
{
	const struct lttng_condition_event_rule_matches
			*event_rule_matches_cond = container_of(condition,
					const struct lttng_condition_event_rule_matches,
					parent);
	struct lttng_capture_descriptor *desc = NULL;
	struct lttng_bytecode *bytecode = NULL;
	unsigned int count;
	enum lttng_condition_status status;

	if (!condition || !IS_EVENT_RULE_MATCHES_CONDITION(condition)) {
		goto end;
	}

	status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
			condition, &count);
	if (status != LTTNG_CONDITION_STATUS_OK) {
		goto end;
	}

	if (index >= count) {
		goto end;
	}

	desc = lttng_dynamic_pointer_array_get_pointer(
			&event_rule_matches_cond->capture_descriptors, index);
	if (desc == NULL) {
		goto end;
	}

	bytecode = desc->bytecode;
end:
	return bytecode;
}
