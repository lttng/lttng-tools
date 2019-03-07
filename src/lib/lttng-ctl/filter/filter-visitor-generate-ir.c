/*
 * filter-visitor-generate-ir.c
 *
 * LTTng filter generate intermediate representation
 *
 * Copyright 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
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
	case IR_DATA_EXPRESSION:
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
void free_load_expression(struct ir_load_expression *load_expression)
{
	struct ir_load_expression_op *exp_op;

	if (!load_expression)
		return;
	exp_op = load_expression->child;
	for (;;) {
		struct ir_load_expression_op *prev_exp_op;

		if (!exp_op)
			break;
		switch (exp_op->type) {
		case IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT:
		case IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT:
		case IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT:
		case IR_LOAD_EXPRESSION_GET_INDEX:
		case IR_LOAD_EXPRESSION_LOAD_FIELD:
			break;
		case IR_LOAD_EXPRESSION_GET_SYMBOL:
			free(exp_op->u.symbol);
			break;
		}
		prev_exp_op = exp_op;
		exp_op = exp_op->next;
		free(prev_exp_op);
	}
	free(load_expression);
}

/*
 * Returns the first node of the chain, after initializing the next
 * pointers.
 */
static
struct filter_node *load_expression_get_forward_chain(struct filter_node *node)
{
	struct filter_node *prev_node;

	for (;;) {
		assert(node->type == NODE_EXPRESSION);
		prev_node = node;
		node = node->u.expression.prev;
		if (!node) {
			break;
		}
		node->u.expression.next = prev_node;
	}
	return prev_node;
}

static
struct ir_load_expression *create_load_expression(struct filter_node *node)
{
	struct ir_load_expression *load_exp;
	struct ir_load_expression_op *load_exp_op, *prev_op;
	char *str;

	/* Get forward chain. */
	node = load_expression_get_forward_chain(node);
	if (!node)
		return NULL;
	load_exp = calloc(sizeof(struct ir_load_expression), 1);
	if (!load_exp)
		return NULL;

	/* Root */
	load_exp_op = calloc(sizeof(struct ir_load_expression_op), 1);
	if (!load_exp_op)
		goto error;
	load_exp->child = load_exp_op;
	str = node->u.expression.u.string;
	if (!strcmp(str, "$ctx")) {
		load_exp_op->type = IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT;
		node = node->u.expression.next;
		if (!node) {
			fprintf(stderr, "[error] Expecting identifier after \'%s\'\n", str);
			goto error;
		}
		str = node->u.expression.u.string;
	} else if (!strcmp(str, "$app")) {
		load_exp_op->type = IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT;
		node = node->u.expression.next;
		if (!node) {
			fprintf(stderr, "[error] Expecting identifier after \'%s\'\n", str);
			goto error;
		}
		str = node->u.expression.u.string;
	} else if (str[0] == '$') {
		fprintf(stderr, "[error] Unexpected identifier \'%s\'\n", str);
		goto error;
	} else {
		load_exp_op->type = IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT;
	}

	for (;;) {
		struct filter_node *bracket_node;

		prev_op = load_exp_op;
		load_exp_op = calloc(sizeof(struct ir_load_expression_op), 1);
		if (!load_exp_op)
			goto error;
		prev_op->next = load_exp_op;
		load_exp_op->type = IR_LOAD_EXPRESSION_GET_SYMBOL;
		load_exp_op->u.symbol = strdup(str);
		if (!load_exp_op->u.symbol)
			goto error;

		/* Explore brackets from current node. */
		for (bracket_node = node->u.expression.next_bracket;
				bracket_node != NULL;
				bracket_node = bracket_node->u.expression.next_bracket) {
			prev_op = load_exp_op;
			load_exp_op = calloc(sizeof(struct ir_load_expression_op), 1);
			if (!load_exp_op)
				goto error;
			prev_op->next = load_exp_op;
			load_exp_op->type = IR_LOAD_EXPRESSION_GET_INDEX;
			load_exp_op->u.index = bracket_node->u.expression.u.constant;
		}
		/* Go to next chain element. */
		node = node->u.expression.next;
		if (!node)
			break;
		str = node->u.expression.u.string;
	}
	/* Add final load field */
	prev_op = load_exp_op;
	load_exp_op = calloc(sizeof(struct ir_load_expression_op), 1);
	if (!load_exp_op)
		goto error;
	prev_op->next = load_exp_op;
	load_exp_op->type = IR_LOAD_EXPRESSION_LOAD_FIELD;
	return load_exp;

error:
	free_load_expression(load_exp);
	return NULL;
}

static
struct ir_op *make_op_load_expression(struct filter_node *node,
		enum ir_side side)
{
	struct ir_op *op;

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_LOAD;
	op->data_type = IR_DATA_EXPRESSION;
	op->signedness = IR_SIGN_DYN;
	op->side = side;
	op->u.load.u.expression = create_load_expression(node);
	if (!op->u.load.u.expression) {
		goto error;
	}
	return op;

error:
	free_load_expression(op->u.load.u.expression);
	free(op);
	return NULL;
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
struct ir_op *make_op_unary_bit_not(struct ir_op *child, enum ir_side side)
{
	return make_op_unary(AST_UNARY_BIT_NOT, "~", child->signedness,
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
struct ir_op *make_op_binary_bitwise(enum op_type bin_op_type,
		const char *op_str, struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	struct ir_op *op = NULL;

	if (left->data_type == IR_DATA_UNKNOWN
		|| right->data_type == IR_DATA_UNKNOWN) {
		fprintf(stderr, "[error] bitwise binary operation '%s' has unknown operand type\n", op_str);
		goto error;

	}
	if (left->data_type == IR_DATA_STRING
		|| right->data_type == IR_DATA_STRING) {
		fprintf(stderr, "[error] bitwise binary operation '%s' cannot have string operand\n", op_str);
		goto error;
	}
	if (left->data_type == IR_DATA_FLOAT
		|| right->data_type == IR_DATA_FLOAT) {
		fprintf(stderr, "[error] bitwise binary operation '%s' cannot have floating point operand\n", op_str);
		goto error;
	}

	op = calloc(sizeof(struct ir_op), 1);
	if (!op)
		return NULL;
	op->op = IR_OP_BINARY;
	op->u.binary.type = bin_op_type;
	op->u.binary.left = left;
	op->u.binary.right = right;

	/* we return a signed numeric */
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
struct ir_op *make_op_binary_bitwise_rshift(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_bitwise(AST_OP_BIT_RSHIFT, ">>", left, right, side);
}

static
struct ir_op *make_op_binary_bitwise_lshift(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_bitwise(AST_OP_BIT_LSHIFT, "<<", left, right, side);
}

static
struct ir_op *make_op_binary_bitwise_and(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_bitwise(AST_OP_BIT_AND, "&", left, right, side);
}

static
struct ir_op *make_op_binary_bitwise_or(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_bitwise(AST_OP_BIT_OR, "|", left, right, side);
}

static
struct ir_op *make_op_binary_bitwise_xor(struct ir_op *left, struct ir_op *right,
		enum ir_side side)
{
	return make_op_binary_bitwise(AST_OP_BIT_XOR, "^", left, right, side);
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
		case IR_DATA_EXPRESSION:
			free_load_expression(op->u.load.u.expression);
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
	case AST_EXP_GLOBAL_IDENTIFIER:
		return make_op_load_expression(node, side);
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
	 * The following binary operators other than comparators and
	 * logical and/or are not supported yet.
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

	case AST_OP_BIT_RSHIFT:
	case AST_OP_BIT_LSHIFT:
	case AST_OP_BIT_AND:
	case AST_OP_BIT_OR:
	case AST_OP_BIT_XOR:
		lchild = generate_ir_recursive(ctx, node->u.op.lchild, IR_LEFT);
		if (!lchild)
			return NULL;
		rchild = generate_ir_recursive(ctx, node->u.op.rchild, IR_RIGHT);
		if (!rchild) {
			filter_free_ir_recursive(lchild);
			return NULL;
		}
		break;

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
	case AST_OP_BIT_RSHIFT:
		op = make_op_binary_bitwise_rshift(lchild, rchild, side);
		break;
	case AST_OP_BIT_LSHIFT:
		op = make_op_binary_bitwise_lshift(lchild, rchild, side);
		break;
	case AST_OP_BIT_AND:
		op = make_op_binary_bitwise_and(lchild, rchild, side);
		break;
	case AST_OP_BIT_OR:
		op = make_op_binary_bitwise_or(lchild, rchild, side);
		break;
	case AST_OP_BIT_XOR:
		op = make_op_binary_bitwise_xor(lchild, rchild, side);
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
	case AST_UNARY_BIT_NOT:
	{
		struct ir_op *op, *child;

		child = generate_ir_recursive(ctx, node->u.unary_op.child,
					side);
		if (!child)
			return NULL;
		op = make_op_unary_bit_not(child, side);
		if (!op) {
			filter_free_ir_recursive(child);
			return NULL;
		}
		return op;
	}
	}

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
