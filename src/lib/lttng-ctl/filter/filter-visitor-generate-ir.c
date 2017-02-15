/*
 * filter-visitor-generate-ir.c
 *
 * LTTng filter generate intermediate representation
 *
 * Copyright 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include "filter-ast.h"
#include "filter-parser.h"
#include "filter-ir.h"

#include <common/macros.h>
#include <common/string-utils/string-utils.h>

static
struct ir_op *generate_ir_recursive(struct filter_parser_ctx *ctx,
		struct filter_node *node, enum ir_side side);

static
struct ir_op *make_op_root(struct ir_op *child, enum ir_side side)
{
	struct ir_op *op;

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	switch (child->data_type) {
	case IR_DATA_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown root child data type\n");
		free(op);
		return NULL;
	case IR_DATA_STRING:
		fprintf(stderr, "[error] String cannot be root data type\n");
		free(op);
		return NULL;
	case IR_DATA_NUMERIC:
	case IR_DATA_FIELD_REF:
	case IR_DATA_GET_CONTEXT_REF:
		/* ok */
		break;
	}
	op->op = IR_OP_ROOT;
	op->side = side;
	op->data_type = child->data_type;
	op->signedness = child->signedness;
	op->u.root.child = child;
	return op;
}

static
enum ir_load_string_type get_literal_string_type(const char *string)
{
	assert(string);

	if (strutils_is_star_glob_pattern(string)) {
		if (strutils_is_star_at_the_end_only_glob_pattern(string)) {
			return IR_LOAD_STRING_TYPE_GLOB_STAR_END;
		}

		return IR_LOAD_STRING_TYPE_GLOB_STAR;
	}

	return IR_LOAD_STRING_TYPE_PLAIN;
}

static
struct ir_op *make_op_load_string(char *string, enum ir_side side)
{
	struct ir_op *op;

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_LOAD;
	op->data_type = IR_DATA_STRING;
	op->signedness = IR_SIGN_UNKNOWN;
	op->side = side;
	op->u.load.u.string.type = get_literal_string_type(string);
	op->u.load.u.string.value = strdup(string);
	if (!op->u.load.u.string.value) {
		free(op);
		return NULL;
	}
	return op;
}

static
struct ir_op *make_op_load_numeric(int64_t v, enum ir_side side)
{
	struct ir_op *op;

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_LOAD;
	op->data_type = IR_DATA_NUMERIC;
	/* TODO: for now, all numeric values are signed */
	op->signedness = IR_SIGNED;
	op->side = side;
	op->u.load.u.num = v;
	return op;
}

static
struct ir_op *make_op_load_float(double v, enum ir_side side)
{
	struct ir_op *op;

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_LOAD;
	op->data_type = IR_DATA_FLOAT;
	op->signedness = IR_SIGN_UNKNOWN;
	op->side = side;
	op->u.load.u.flt = v;
	return op;
}

static
struct ir_op *make_op_load_field_ref(char *string, enum ir_side side)
{
	struct ir_op *op;

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_LOAD;
	op->data_type = IR_DATA_FIELD_REF;
	op->signedness = IR_SIGN_DYN;
	op->side = side;
	op->u.load.u.ref = strdup(string);
	if (!op->u.load.u.ref) {
		free(op);
		return NULL;
	}
	return op;
}

static
struct ir_op *make_op_load_get_context_ref(char *string, enum ir_side side)
{
	struct ir_op *op;

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_LOAD;
	op->data_type = IR_DATA_GET_CONTEXT_REF;
	op->signedness = IR_SIGN_DYN;
	op->side = side;
	op->u.load.u.ref = strdup(string);
	if (!op->u.load.u.ref) {
		free(op);
		return NULL;
	}
	return op;
}

static
struct ir_op *make_op_unary(enum unary_op_type unary_op_type,
			const char *op_str, enum ir_op_signedness signedness,
			struct ir_op *child, enum ir_side side)
{
	struct ir_op *op = NULL;

	if (child->data_type == IR_DATA_STRING) {
		fprintf(stderr, "[error] unary operation '%s' not allowed on string literal\n", op_str);
		goto error;
	}

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_UNARY;
	op->data_type = child->data_type;
	op->signedness = signedness;
	op->side = side;
	op->u.unary.type = unary_op_type;
	op->u.unary.child = child;
	return op;

error:
	free(op);
	return NULL;
}

/*
 * unary + is pretty much useless.
 */
static
struct ir_op *make_op_unary_plus(struct ir_op *child, enum ir_side side)
{
	return make_op_unary(AST_UNARY_PLUS, "+", child->signedness,
			child, side);
}

static
struct ir_op *make_op_unary_minus(struct ir_op *child, enum ir_side side)
{
	return make_op_unary(AST_UNARY_MINUS, "-", child->signedness,
			child, side);
}

static
struct ir_op *make_op_unary_not(struct ir_op *child, enum ir_side side)
{
	return make_op_unary(AST_UNARY_NOT, "!", child->signedness,
			child, side);
}

static
struct ir_op *make_op_binary_compare(enum op_type bin_op_type,
		const char *op_str, struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	struct ir_op *op = NULL;

	if (left->data_type == IR_DATA_UNKNOWN
		|| right->data_type == IR_DATA_UNKNOWN) {
		fprintf(stderr, "[error] binary operation '%s' has unknown operand type\n", op_str);
		goto error;

	}
	if ((left->data_type == IR_DATA_STRING
		&& (right->data_type == IR_DATA_NUMERIC || right->data_type == IR_DATA_FLOAT))
		|| ((left->data_type == IR_DATA_NUMERIC || left->data_type == IR_DATA_FLOAT) &&
			right->data_type == IR_DATA_STRING)) {
		fprintf(stderr, "[error] binary operation '%s' operand type mismatch\n", op_str);
		goto error;
	}

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_BINARY;
	op->u.binary.type = bin_op_type;
	op->u.binary.left = left;
	op->u.binary.right = right;

	/* we return a boolean, represented as signed numeric */
	op->data_type = IR_DATA_NUMERIC;
	op->signedness = IR_SIGNED;
	op->side = side;

	return op;

error:
	free(op);
	return NULL;
}

static
struct ir_op *make_op_binary_eq(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_compare(AST_OP_EQ, "==", left, right, side);
}

static
struct ir_op *make_op_binary_ne(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_compare(AST_OP_NE, "!=", left, right, side);
}

static
struct ir_op *make_op_binary_gt(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_compare(AST_OP_GT, ">", left, right, side);
}

static
struct ir_op *make_op_binary_lt(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_compare(AST_OP_LT, "<", left, right, side);
}

static
struct ir_op *make_op_binary_ge(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_compare(AST_OP_GE, ">=", left, right, side);
}

static
struct ir_op *make_op_binary_le(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_compare(AST_OP_LE, "<=", left, right, side);
}

static
struct ir_op *make_op_binary_logical(enum op_type bin_op_type,
		const char *op_str, struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	struct ir_op *op = NULL;

	if (left->data_type == IR_DATA_UNKNOWN
		|| right->data_type == IR_DATA_UNKNOWN) {
		fprintf(stderr, "[error] binary operation '%s' has unknown operand type\n", op_str);
		goto error;

	}
	if (left->data_type == IR_DATA_STRING
		|| right->data_type == IR_DATA_STRING) {
		fprintf(stderr, "[error] logical binary operation '%s' cannot have string operand\n", op_str);
		goto error;
	}

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_LOGICAL;
	op->u.binary.type = bin_op_type;
	op->u.binary.left = left;
	op->u.binary.right = right;

	/* we return a boolean, represented as signed numeric */
	op->data_type = IR_DATA_NUMERIC;
	op->signedness = IR_SIGNED;
	op->side = side;

	return op;

error:
	free(op);
	return NULL;
}

static
struct ir_op *make_op_binary_logical_and(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_logical(AST_OP_AND, "&&", left, right, side);
}

static
struct ir_op *make_op_binary_logical_or(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_logical(AST_OP_OR, "||", left, right, side);
}

static
void filter_free_ir_recursive(struct ir_op *op)
{
	if (!op)
		return;
	switch (op->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown op type in %s\n",
			__func__);
		break;
	case IR_OP_ROOT:
		filter_free_ir_recursive(op->u.root.child);
		break;
	case IR_OP_LOAD:
		switch (op->data_type) {
		case IR_DATA_STRING:
			free(op->u.load.u.string.value);
			break;
		case IR_DATA_FIELD_REF:		/* fall-through */
		case IR_DATA_GET_CONTEXT_REF:
			free(op->u.load.u.ref);
			break;
		default:
			break;
		}
		break;
	case IR_OP_UNARY:
		filter_free_ir_recursive(op->u.unary.child);
		break;
	case IR_OP_BINARY:
		filter_free_ir_recursive(op->u.binary.left);
		filter_free_ir_recursive(op->u.binary.right);
		break;
	case IR_OP_LOGICAL:
		filter_free_ir_recursive(op->u.logical.left);
		filter_free_ir_recursive(op->u.logical.right);
		break;
	}
	free(op);
}

static
struct ir_op *make_expression(struct filter_parser_ctx *ctx,
		struct filter_node *node, enum ir_side side)
{
	switch (node->u.expression.type) {
	case AST_EXP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown expression type\n", __func__);
		return NULL;

	case AST_EXP_STRING:
		return make_op_load_string(node->u.expression.u.string, side);
	case AST_EXP_CONSTANT:
		return make_op_load_numeric(node->u.expression.u.constant,
					side);
	case AST_EXP_FLOAT_CONSTANT:
		return make_op_load_float(node->u.expression.u.float_constant,
					side);
	case AST_EXP_IDENTIFIER:
		if (node->u.expression.pre_op != AST_LINK_UNKNOWN) {
			fprintf(stderr, "[error] %s: dotted and dereferenced identifiers not supported\n", __func__);
			return NULL;
		}
		return make_op_load_field_ref(node->u.expression.u.identifier,
					side);
	case AST_EXP_GLOBAL_IDENTIFIER:
	{
		const char *name;

		/*
		 * We currently only support $ctx (context) and $app
		 * identifiers.
		 */
		if (strncmp(node->u.expression.u.identifier,
				"$ctx.", strlen("$ctx.")) != 0
			&& strncmp(node->u.expression.u.identifier,
				"$app.", strlen("$app.")) != 0) {
			fprintf(stderr, "[error] %s: \"%s\" global identifier is unknown. Only \"$ctx\" and \"$app\" are currently implemented.\n", __func__, node->u.expression.u.identifier);
			return NULL;
		}
		name = strchr(node->u.expression.u.identifier, '.');
		if (!name) {
			fprintf(stderr, "[error] %s: Expecting '.'\n", __func__);
			return NULL;
		}
		name++;	/* Skip . */
		if (!strlen(name)) {
			fprintf(stderr, "[error] %s: Expecting a context name, e.g. \'$ctx.name\'.\n", __func__);
			return NULL;
		}
		return make_op_load_get_context_ref(node->u.expression.u.identifier,
					side);
	}
	case AST_EXP_NESTED:
		return generate_ir_recursive(ctx, node->u.expression.u.child,
					side);
	}
}

static
struct ir_op *make_op(struct filter_parser_ctx *ctx,
		struct filter_node *node, enum ir_side side)
{
	struct ir_op *op = NULL, *lchild, *rchild;
	const char *op_str = "?";

	switch (node->u.op.type) {
	case AST_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown binary op type\n", __func__);
		return NULL;

	/*
	 * Binary operators other than comparators and logical and/or
	 * are not supported. If we ever want to support those, we will
	 * need a stack for the general case rather than just 2
	 * registers (see bytecode).
	 */
	case AST_OP_MUL:
		op_str = "*";
		goto error_not_supported;
	case AST_OP_DIV:
		op_str = "/";
		goto error_not_supported;
	case AST_OP_MOD:
		op_str = "%";
		goto error_not_supported;
	case AST_OP_PLUS:
		op_str = "+";
		goto error_not_supported;
	case AST_OP_MINUS:
		op_str = "-";
		goto error_not_supported;
	case AST_OP_RSHIFT:
		op_str = ">>";
		goto error_not_supported;
	case AST_OP_LSHIFT:
		op_str = "<<";
		goto error_not_supported;
	case AST_OP_BIN_AND:
		op_str = "&";
		goto error_not_supported;
	case AST_OP_BIN_OR:
		op_str = "|";
		goto error_not_supported;
	case AST_OP_BIN_XOR:
		op_str = "^";
		goto error_not_supported;

	case AST_OP_EQ:
	case AST_OP_NE:
	case AST_OP_GT:
	case AST_OP_LT:
	case AST_OP_GE:
	case AST_OP_LE:
		lchild = generate_ir_recursive(ctx, node->u.op.lchild, IR_LEFT);
		if (!lchild)
			return NULL;
		rchild = generate_ir_recursive(ctx, node->u.op.rchild, IR_RIGHT);
		if (!rchild) {
			filter_free_ir_recursive(lchild);
			return NULL;
		}
		break;

	case AST_OP_AND:
	case AST_OP_OR:
		/*
		 * Both children considered as left, since we need to
		 * populate R0.
		 */
		lchild = generate_ir_recursive(ctx, node->u.op.lchild, IR_LEFT);
		if (!lchild)
			return NULL;
		rchild = generate_ir_recursive(ctx, node->u.op.rchild, IR_LEFT);
		if (!rchild) {
			filter_free_ir_recursive(lchild);
			return NULL;
		}
		break;
	}

	switch (node->u.op.type) {
	case AST_OP_AND:
		op = make_op_binary_logical_and(lchild, rchild, side);
		break;
	case AST_OP_OR:
		op = make_op_binary_logical_or(lchild, rchild, side);
		break;
	case AST_OP_EQ:
		op = make_op_binary_eq(lchild, rchild, side);
		break;
	case AST_OP_NE:
		op = make_op_binary_ne(lchild, rchild, side);
		break;
	case AST_OP_GT:
		op = make_op_binary_gt(lchild, rchild, side);
		break;
	case AST_OP_LT:
		op = make_op_binary_lt(lchild, rchild, side);
		break;
	case AST_OP_GE:
		op = make_op_binary_ge(lchild, rchild, side);
		break;
	case AST_OP_LE:
		op = make_op_binary_le(lchild, rchild, side);
		break;
	default:
		break;
	}

	if (!op) {
		filter_free_ir_recursive(rchild);
		filter_free_ir_recursive(lchild);
	}
	return op;

error_not_supported:
	fprintf(stderr, "[error] %s: binary operation '%s' not supported\n",
		__func__, op_str);
	return NULL;
}

static
struct ir_op *make_unary_op(struct filter_parser_ctx *ctx,
		struct filter_node *node, enum ir_side side)
{
	const char *op_str = "?";

	switch (node->u.unary_op.type) {
	case AST_UNARY_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown unary op type\n", __func__);
		return NULL;

	case AST_UNARY_PLUS:
	{
		struct ir_op *op, *child;

		child = generate_ir_recursive(ctx, node->u.unary_op.child,
					side);
		if (!child)
			return NULL;
		op = make_op_unary_plus(child, side);
		if (!op) {
			filter_free_ir_recursive(child);
			return NULL;
		}
		return op;
	}
	case AST_UNARY_MINUS:
	{
		struct ir_op *op, *child;

		child = generate_ir_recursive(ctx, node->u.unary_op.child,
					side);
		if (!child)
			return NULL;
		op = make_op_unary_minus(child, side);
		if (!op) {
			filter_free_ir_recursive(child);
			return NULL;
		}
		return op;
	}
	case AST_UNARY_NOT:
	{
		struct ir_op *op, *child;

		child = generate_ir_recursive(ctx, node->u.unary_op.child,
					side);
		if (!child)
			return NULL;
		op = make_op_unary_not(child, side);
		if (!op) {
			filter_free_ir_recursive(child);
			return NULL;
		}
		return op;
	}
	case AST_UNARY_BIN_NOT:
	{
		op_str = "~";
		goto error_not_supported;
	}
	}

error_not_supported:
	fprintf(stderr, "[error] %s: unary operation '%s' not supported\n",
		__func__, op_str);
	return NULL;
}

static
struct ir_op *generate_ir_recursive(struct filter_parser_ctx *ctx,
		struct filter_node *node, enum ir_side side)
{
	switch (node->type) {
	case NODE_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown node type\n", __func__);
		return NULL;

	case NODE_ROOT:
	{
		struct ir_op *op, *child;

		child = generate_ir_recursive(ctx, node->u.root.child,
					side);
		if (!child)
			return NULL;
		op = make_op_root(child, side);
		if (!op) {
			filter_free_ir_recursive(child);
			return NULL;
		}
		return op;
	}
	case NODE_EXPRESSION:
		return make_expression(ctx, node, side);
	case NODE_OP:
		return make_op(ctx, node, side);
	case NODE_UNARY_OP:
		return make_unary_op(ctx, node, side);
	}
	return 0;
}

LTTNG_HIDDEN
void filter_ir_free(struct filter_parser_ctx *ctx)
{
	filter_free_ir_recursive(ctx->ir_root);
	ctx->ir_root = NULL;
}

LTTNG_HIDDEN
int filter_visitor_ir_generate(struct filter_parser_ctx *ctx)
{
	struct ir_op *op;

	op = generate_ir_recursive(ctx, &ctx->ast->root, IR_LEFT);
	if (!op) {
		return -EINVAL;
	}
	ctx->ir_root = op;
	return 0;
}
