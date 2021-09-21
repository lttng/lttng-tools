/*
 * event-expr.c
 *
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <stddef.h>

#include <common/bytecode/bytecode.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/mi-lttng.h>
#include <lttng/event-expr-internal.h>
#include <lttng/event-expr.h>
#include <stdio.h>

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

	LTTNG_ASSERT(name);
	expr->name = strdup(name);
	if (!expr->name) {
		goto error;
	}

	goto end;

error:
	if (expr) {
		lttng_event_expr_destroy(&expr->parent);
	}
	expr = NULL;

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
	struct lttng_event_expr *ret_parent_expr;

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

	ret_parent_expr = &expr->parent;
	goto end;

error:
	if (expr) {
		lttng_event_expr_destroy(&expr->parent);
	}
	ret_parent_expr = NULL;

end:
	return ret_parent_expr;
}

struct lttng_event_expr *lttng_event_expr_array_field_element_create(
		struct lttng_event_expr *array_field_expr,
		unsigned int index)
{
	struct lttng_event_expr_array_field_element *expr = NULL;
	struct lttng_event_expr *ret_parent_expr;

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
	ret_parent_expr = &expr->parent;
	goto end;

error:
	ret_parent_expr = NULL;

end:
	return ret_parent_expr;
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

static int event_expr_to_bytecode_recursive(const struct lttng_event_expr *expr,
		struct lttng_bytecode_alloc **bytecode,
		struct lttng_bytecode_alloc **bytecode_reloc)
{
	int status;
	enum lttng_event_expr_status event_expr_status;

	switch (lttng_event_expr_get_type(expr)) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
	{
		const char *name;

		status = bytecode_push_get_payload_root(bytecode);
		if (status) {
			ERR("Failed to get payload root from bytecode");
			goto end;
		}

		name = lttng_event_expr_event_payload_field_get_name(expr);
		if (!name) {
			ERR("Failed to get payload field name from event expression");
			status = -1;
			goto end;
		}

		status = bytecode_push_get_symbol(
				bytecode, bytecode_reloc, name);
		if (status) {
			ERR("Failed to push 'get symbol %s' in bytecode", name);
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
	{
		const char *name;

		status = bytecode_push_get_context_root(bytecode);
		if (status) {
			ERR("Failed to get context root from bytecode");
			goto end;
		}

		name = lttng_event_expr_channel_context_field_get_name(expr);
		if (!name) {
			ERR("Failed to get channel context field name from event expression");
			status = -1;
			goto end;
		}

		status = bytecode_push_get_symbol(
				bytecode, bytecode_reloc, name);
		if (status) {
			ERR("Failed to push 'get symbol %s' in bytecode", name);
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
	{
		int ret;
		char *name = NULL;
		const char *provider_name, *type_name;

		status = bytecode_push_get_app_context_root(bytecode);
		if (status) {
			ERR("Failed to get application context root from bytecode");
			goto end;
		}

		provider_name = lttng_event_expr_app_specific_context_field_get_provider_name(
				expr);
		if (!provider_name) {
			ERR("Failed to get application context provider name from event expression");
			status = -1;
			goto end;
		}

		type_name = lttng_event_expr_app_specific_context_field_get_type_name(
				expr);
		if (!type_name) {
			ERR("Failed to get application context type name from event expression");
			status = -1;
			goto end;
		}

		/*
		 * Reconstitute the app context field name from its two parts.
		 */
		ret = asprintf(&name, "%s:%s", provider_name, type_name);
		if (ret < 0) {
			PERROR("Failed to format application specific context: provider_name = '%s', type_name = '%s'",
					provider_name, type_name);
			status = -1;
			goto end;
		}

		status = bytecode_push_get_symbol(
				bytecode, bytecode_reloc, name);
		free(name);
		if (status) {
			ERR("Failed to push 'get symbol %s:%s' in bytecode",
					provider_name, type_name);
			goto end;
		}

		break;
	}
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		unsigned int index;
		const struct lttng_event_expr *parent;

		parent = lttng_event_expr_array_field_element_get_parent_expr(
				expr);
		if (!parent) {
			ERR("Failed to get parent expression from array event expression");
			status = -1;
			goto end;
		}

		status = event_expr_to_bytecode_recursive(
				parent, bytecode, bytecode_reloc);
		if (status) {
			goto end;
		}

		event_expr_status =
				lttng_event_expr_array_field_element_get_index(
						expr, &index);
		if (event_expr_status != LTTNG_EVENT_EXPR_STATUS_OK) {
			ERR("Failed to get array field element index from event expression");
			status = -1;
			goto end;
		}

		status = bytecode_push_get_index_u64(bytecode, index);
		if (status) {
			ERR("Failed to push 'get index %u' in bytecode", index);
			goto end;
		}

		break;
	}
	default:
		abort();
	}

	status = 0;
end:
	return status;
}

int lttng_event_expr_to_bytecode(const struct lttng_event_expr *expr,
		struct lttng_bytecode **bytecode_out)
{
	int status;
	struct return_op ret_insn;
	struct lttng_bytecode_alloc *bytecode = NULL;
	struct lttng_bytecode_alloc *bytecode_reloc = NULL;

	status = bytecode_init(&bytecode);
	if (status) {
		ERR("Failed to initialize bytecode");
		goto end;
	}

	status = bytecode_init(&bytecode_reloc);
	if (status) {
		ERR("Failed to initialize relocation bytecode");
		goto end;
	}

	status = event_expr_to_bytecode_recursive(
			expr, &bytecode, &bytecode_reloc);
	if (status) {
		/* Errors already logged. */
		goto end;
	}

	ret_insn.op = BYTECODE_OP_RETURN;
	bytecode_push(&bytecode, &ret_insn, 1, sizeof(ret_insn));

	/* Append symbol table to bytecode. */
	bytecode->b.reloc_table_offset = bytecode_get_len(&bytecode->b);
	status = bytecode_push(&bytecode, bytecode_reloc->b.data, 1,
			bytecode_get_len(&bytecode_reloc->b));
	if (status) {
		ERR("Failed to push symbol table to bytecode");
		goto end;
	}

	/* Copy the `lttng_bytecode` out of the `lttng_bytecode_alloc`.  */
	*bytecode_out = lttng_bytecode_copy(&bytecode->b);
	if (!*bytecode_out) {
		status = -1;
		goto end;
	}

end:
	if (bytecode) {
		free(bytecode);
	}

	if (bytecode_reloc) {
		free(bytecode_reloc);
	}

	return status;
}

static
enum lttng_error_code lttng_event_expr_event_payload_field_mi_serialize(
		const struct lttng_event_expr *expression,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	const char *name = NULL;

	LTTNG_ASSERT(expression);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(expression->type == LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD);

	name = lttng_event_expr_event_payload_field_get_name(expression);
	LTTNG_ASSERT(name);

	/* Open event expr payload field element. */
	ret = mi_lttng_writer_open_element(
			writer, mi_lttng_element_event_expr_payload_field);
	if (ret) {
		goto mi_error;
	}

	/* Name. */
	ret = mi_lttng_writer_write_element_string(
			writer, config_element_name, name);
	if (ret) {
		goto mi_error;
	}

	/* Close event expr payload field element. */
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

static
enum lttng_error_code lttng_event_expr_channel_context_field_mi_serialize(
		const struct lttng_event_expr *expression,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	const char *name = NULL;

	LTTNG_ASSERT(expression);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(expression->type == LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD);

	name = lttng_event_expr_channel_context_field_get_name(expression);
	LTTNG_ASSERT(name);

	/* Open event expr channel context field element. */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_event_expr_channel_context_field);
	if (ret) {
		goto mi_error;
	}

	/* Name. */
	ret = mi_lttng_writer_write_element_string(
			writer, config_element_name, name);
	if (ret) {
		goto mi_error;
	}

	/* Close event expr channel context field element. */
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

static
enum lttng_error_code lttng_event_expr_app_specific_context_field_mi_serialize(
		const struct lttng_event_expr *expression,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	const char *provider_name = NULL;
	const char *type_name = NULL;

	LTTNG_ASSERT(expression);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(expression->type ==
			LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD);

	provider_name = lttng_event_expr_app_specific_context_field_get_provider_name(
			expression);
	LTTNG_ASSERT(provider_name);

	type_name = lttng_event_expr_app_specific_context_field_get_type_name(
			expression);
	LTTNG_ASSERT(provider_name);

	/* Open event expr app specific context field element. */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_event_expr_app_specific_context_field);
	if (ret) {
		goto mi_error;
	}

	/* Provider name. */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_event_expr_provider_name,
			provider_name);
	if (ret) {
		goto mi_error;
	}

	/* Type name. */
	ret = mi_lttng_writer_write_element_string(writer,
			mi_lttng_element_event_expr_type_name, type_name);
	if (ret) {
		goto mi_error;
	}

	/* Close event expr app specific context field element. */
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

static
enum lttng_error_code lttng_event_expr_array_field_element_mi_serialize(
		const struct lttng_event_expr *expression,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_event_expr_status status;
	const struct lttng_event_expr *parent_expr = NULL;
	unsigned int index;

	LTTNG_ASSERT(expression);
	LTTNG_ASSERT(writer);
	LTTNG_ASSERT(expression->type == LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT);

	status = lttng_event_expr_array_field_element_get_index(
			expression, &index);
	LTTNG_ASSERT(status == LTTNG_EVENT_EXPR_STATUS_OK);

	parent_expr = lttng_event_expr_array_field_element_get_parent_expr(
			expression);
	LTTNG_ASSERT(parent_expr != NULL);

	/* Open event expr array field element. */
	ret = mi_lttng_writer_open_element(writer,
			mi_lttng_element_event_expr_array_field_element);
	if (ret) {
		goto mi_error;
	}

	/* Index. */
	ret = mi_lttng_writer_write_element_unsigned_int(
			writer, mi_lttng_element_event_expr_index, index);
	if (ret) {
		goto mi_error;
	}

	/* Parent expression. */
	ret_code = lttng_event_expr_mi_serialize(parent_expr, writer);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	/* Close event expr array field element. */
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

enum lttng_error_code lttng_event_expr_mi_serialize(
		const struct lttng_event_expr *expression,
		struct mi_writer *writer)
{
	int ret;
	enum lttng_error_code ret_code;

	LTTNG_ASSERT(expression);
	LTTNG_ASSERT(writer);

	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_event_expr);
	if (ret) {
		goto mi_error;
	}

	switch (expression->type) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
		ret_code = lttng_event_expr_event_payload_field_mi_serialize(
				expression, writer);
		break;
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
		ret_code = lttng_event_expr_channel_context_field_mi_serialize(
				expression, writer);
		break;
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
		ret_code = lttng_event_expr_app_specific_context_field_mi_serialize(
				expression, writer);
		break;
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
		ret_code = lttng_event_expr_array_field_element_mi_serialize(
				expression, writer);
		break;
	default:
		abort();
	}

	if (ret_code != LTTNG_OK) {
		goto end;
	}

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
