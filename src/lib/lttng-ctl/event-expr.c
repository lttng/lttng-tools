/*
 * event-expr.c
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <stddef.h>

#include <common/error.h>
#include <common/macros.h>
#include <lttng/event-expr-internal.h>

enum lttng_event_expr_type lttng_event_expr_get_type(
		const struct lttng_event_expr *expr)
{
	enum lttng_event_expr_type type;

	if (!expr) {
		type = LTTNG_EVENT_EXPR_TYPE_INVALID;
		goto end;
	}

	type = expr->type;

end:
	return type;
}

static
struct lttng_event_expr *create_empty_expr(enum lttng_event_expr_type type,
		size_t size)
{
	struct lttng_event_expr *expr;

	expr = zmalloc(size);
	if (!expr) {
		goto end;
	}

	expr->type = type;

end:
	return expr;
}

static
struct lttng_event_expr_field *create_field_event_expr(
		enum lttng_event_expr_type type,
		const char *name)
{
	struct lttng_event_expr_field *expr =
			container_of(
				create_empty_expr(type, sizeof(*expr)),
				struct lttng_event_expr_field, parent);

	if (!expr) {
		goto error;
	}

	assert(name);
	expr->name = strdup(name);
	if (!expr->name) {
		goto error;
	}

	goto end;

error:
	lttng_event_expr_destroy(&expr->parent);

end:
	return expr;
}

struct lttng_event_expr *lttng_event_expr_event_payload_field_create(
		const char *field_name)
{
	struct lttng_event_expr *expr = NULL;

	if (!field_name) {
		goto end;
	}

	expr = &create_field_event_expr(
			LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD,
			field_name)->parent;

end:
	return expr;
}

struct lttng_event_expr *lttng_event_expr_channel_context_field_create(
		const char *field_name)
{
	struct lttng_event_expr *expr = NULL;

	if (!field_name) {
		goto end;
	}

	expr = &create_field_event_expr(
			LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD,
			field_name)->parent;

end:
	return expr;
}

struct lttng_event_expr *lttng_event_expr_app_specific_context_field_create(
		const char *provider_name, const char *type_name)
{
	struct lttng_event_expr_app_specific_context_field *expr = NULL;

	if (!type_name || !provider_name) {
		goto error;
	}

	expr = container_of(create_empty_expr(
			LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD,
			sizeof(*expr)),
			struct lttng_event_expr_app_specific_context_field,
			parent);
	if (!expr) {
		goto error;
	}

	expr->provider_name = strdup(provider_name);
	if (!expr->provider_name) {
		goto error;
	}

	expr->type_name = strdup(type_name);
	if (!expr->type_name) {
		goto error;
	}

	goto end;

error:
	lttng_event_expr_destroy(&expr->parent);

end:
	return &expr->parent;
}

struct lttng_event_expr *lttng_event_expr_array_field_element_create(
		struct lttng_event_expr *array_field_expr,
		unsigned int index)
{
	struct lttng_event_expr_array_field_element *expr = NULL;

	/* The parent array field expression must be an l-value */
	if (!array_field_expr ||
			!lttng_event_expr_is_lvalue(array_field_expr)) {
		goto error;
	}

	expr = container_of(create_empty_expr(
			LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT,
			sizeof(*expr)),
			struct lttng_event_expr_array_field_element,
			parent);
	if (!expr) {
		goto error;
	}

	expr->array_field_expr = array_field_expr;
	expr->index = index;
	goto end;

error:
	lttng_event_expr_destroy(&expr->parent);

end:
	return &expr->parent;
}

const char *lttng_event_expr_event_payload_field_get_name(
		const struct lttng_event_expr *expr)
{
	const char *ret = NULL;

	if (!expr || expr->type != LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD) {
		goto end;
	}

	ret = container_of(expr,
			const struct lttng_event_expr_field, parent)->name;

end:
	return ret;
}

const char *lttng_event_expr_channel_context_field_get_name(
		const struct lttng_event_expr *expr)
{
	const char *ret = NULL;

	if (!expr || expr->type != LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD) {
		goto end;
	}

	ret = container_of(expr,
			const struct lttng_event_expr_field, parent)->name;

end:
	return ret;
}

const char *lttng_event_expr_app_specific_context_field_get_provider_name(
		const struct lttng_event_expr *expr)
{
	const char *ret = NULL;

	if (!expr || expr->type != LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD) {
		goto end;
	}

	ret = container_of(expr,
			const struct lttng_event_expr_app_specific_context_field,
			parent)->provider_name;

end:
	return ret;
}

const char *lttng_event_expr_app_specific_context_field_get_type_name(
		const struct lttng_event_expr *expr)
{
	const char *ret = NULL;

	if (!expr || expr->type != LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD) {
		goto end;
	}

	ret = container_of(expr,
			const struct lttng_event_expr_app_specific_context_field,
			parent)->type_name;

end:
	return ret;
}

const struct lttng_event_expr *
lttng_event_expr_array_field_element_get_parent_expr(
		const struct lttng_event_expr *expr)
{
	const struct lttng_event_expr *ret = NULL;

	if (!expr || expr->type != LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT) {
		goto end;
	}

	ret = container_of(expr,
			const struct lttng_event_expr_array_field_element,
			parent)->array_field_expr;

end:
	return ret;
}

enum lttng_event_expr_status lttng_event_expr_array_field_element_get_index(
		const struct lttng_event_expr *expr, unsigned int *index)
{
	enum lttng_event_expr_status ret = LTTNG_EVENT_EXPR_STATUS_OK;

	if (!expr || expr->type != LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT ||
			!index) {
		ret = LTTNG_EVENT_EXPR_STATUS_INVALID;
		goto end;
	}

	*index = container_of(expr,
			const struct lttng_event_expr_array_field_element,
			parent)->index;

end:
	return ret;
}

bool lttng_event_expr_is_equal(const struct lttng_event_expr *expr_a,
		const struct lttng_event_expr *expr_b)
{
	bool is_equal = true;

	if (!expr_a && !expr_b) {
		/* Both `NULL`: equal */
		goto end;
	}

	if (!expr_a || !expr_b) {
		/* Only one `NULL`: not equal */
		goto not_equal;
	}

	if (expr_a->type != expr_b->type) {
		/* Different types: not equal */
		goto not_equal;
	}

	switch (expr_a->type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		const struct lttng_event_expr_field *field_expr_a =
				container_of(expr_a,
					const struct lttng_event_expr_field,
					parent);
		const struct lttng_event_expr_field *field_expr_b =
				container_of(expr_b,
					const struct lttng_event_expr_field,
					parent);

		if (strcmp(field_expr_a->name, field_expr_b->name) != 0) {
			goto not_equal;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		const struct lttng_event_expr_app_specific_context_field *field_expr_a =
				container_of(expr_a,
					const struct lttng_event_expr_app_specific_context_field,
					parent);
		const struct lttng_event_expr_app_specific_context_field *field_expr_b =
				container_of(expr_b,
					const struct lttng_event_expr_app_specific_context_field,
					parent);

		if (strcmp(field_expr_a->provider_name,
				field_expr_b->provider_name) != 0) {
			goto not_equal;
		}

		if (strcmp(field_expr_a->type_name,
				field_expr_b->type_name) != 0) {
			goto not_equal;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		const struct lttng_event_expr_array_field_element *elem_expr_a =
				container_of(expr_a,
					const struct lttng_event_expr_array_field_element,
					parent);
		const struct lttng_event_expr_array_field_element *elem_expr_b =
				container_of(expr_b,
					const struct lttng_event_expr_array_field_element,
					parent);

		if (!lttng_event_expr_is_equal(elem_expr_a->array_field_expr,
				elem_expr_b->array_field_expr)) {
			goto not_equal;
		}

		if (elem_expr_a->index != elem_expr_b->index) {
			goto not_equal;
		}

		break;
	}
	default:
		break;
	}

	goto end;

not_equal:
	is_equal = false;

end:
	return is_equal;
}

void lttng_event_expr_destroy(struct lttng_event_expr *expr)
{
	if (!expr) {
		goto end;
	}

	switch (expr->type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		struct lttng_event_expr_field *field_expr =
				container_of(expr,
					struct lttng_event_expr_field, parent);

		free(field_expr->name);
		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		struct lttng_event_expr_app_specific_context_field *field_expr =
				container_of(expr,
					struct lttng_event_expr_app_specific_context_field,
					parent);

		free(field_expr->provider_name);
		free(field_expr->type_name);
		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		struct lttng_event_expr_array_field_element *elem_expr =
				container_of(expr,
					struct lttng_event_expr_array_field_element,
					parent);

		lttng_event_expr_destroy(elem_expr->array_field_expr);
		break;
	}
	default:
		break;
	}

	free(expr);

end:
	return;
}
