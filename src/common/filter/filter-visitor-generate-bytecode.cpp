/*
 * filter-visitor-generate-bytecode.c
 *
 * LTTng filter bytecode generation
 *
 * SPDX-FileCopyrightText: 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "common/align.hpp"
#include "common/bytecode/bytecode.hpp"
#include "common/compat/string.hpp"
#include "common/macros.hpp"
#include "common/string-utils/string-utils.hpp"
#include "filter-ast.hpp"
#include "filter-ir.hpp"

#include <common/align.hpp>
#include <common/compat/errno.hpp>
#include <common/compat/string.hpp>

#include <stdlib.h>
#include <string.h>

static int recursive_visit_gen_bytecode(struct filter_parser_ctx *ctx, struct ir_op *node);

static int
bytecode_patch(struct lttng_bytecode_alloc **fb, const void *data, uint16_t offset, uint32_t len)
{
	if (offset >= (*fb)->b.len) {
		return -EINVAL;
	}
	memcpy(&(*fb)->b.data[offset], data, len);
	return 0;
}

static int visit_node_root(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	int ret;
	struct return_op insn;

	/* Visit child */
	ret = recursive_visit_gen_bytecode(ctx, node->u.root.child);
	if (ret)
		return ret;

	/* Generate end of bytecode instruction */
	insn.op = BYTECODE_OP_RETURN;
	return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
}

/*
 * 1: match
 * 0: no match
 * < 0: error
 */
static int load_expression_legacy_match(const struct ir_load_expression *exp,
					enum bytecode_op *op_type,
					char **symbol)
{
	const struct ir_load_expression_op *op;
	bool need_dot = false;

	op = exp->child;
	switch (op->type) {
	case IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT:
		*op_type = BYTECODE_OP_GET_CONTEXT_REF;
		if (strutils_append_str(symbol, "$ctx.")) {
			return -ENOMEM;
		}
		need_dot = false;
		break;
	case IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT:
		*op_type = BYTECODE_OP_GET_CONTEXT_REF;
		if (strutils_append_str(symbol, "$app.")) {
			return -ENOMEM;
		}
		need_dot = false;
		break;
	case IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT:
		*op_type = BYTECODE_OP_LOAD_FIELD_REF;
		need_dot = false;
		break;

	case IR_LOAD_EXPRESSION_GET_SYMBOL:
	case IR_LOAD_EXPRESSION_GET_INDEX:
	case IR_LOAD_EXPRESSION_LOAD_FIELD:
	default:
		return 0; /* no match */
	}

	for (;;) {
		op = op->next;
		if (!op) {
			return 0; /* no match */
		}
		switch (op->type) {
		case IR_LOAD_EXPRESSION_LOAD_FIELD:
			goto end;
		case IR_LOAD_EXPRESSION_GET_SYMBOL:
			if (need_dot && strutils_append_str(symbol, ".")) {
				return -ENOMEM;
			}
			if (strutils_append_str(symbol, op->u.symbol)) {
				return -ENOMEM;
			}
			break;
		default:
			return 0; /* no match */
		}
		need_dot = true;
	}
end:
	return 1; /* Legacy match */
}

/*
 * 1: legacy match
 * 0: no legacy match
 * < 0: error
 */
static int visit_node_load_expression_legacy(struct filter_parser_ctx *ctx,
					     const struct ir_load_expression *exp)
{
	struct load_op *insn = nullptr;
	const auto insn_len = sizeof(struct load_op) + sizeof(struct field_ref);
	struct field_ref ref_offset;
	uint32_t reloc_offset_u32;
	uint16_t reloc_offset;
	enum bytecode_op op_type;
	char *symbol = nullptr;
	int ret;

	ret = load_expression_legacy_match(exp, &op_type, &symbol);
	if (ret <= 0) {
		goto end;
	}
	insn = (load_op *) calloc(insn_len, 1);
	if (!insn) {
		ret = -ENOMEM;
		goto end;
	}
	insn->op = op_type;
	ref_offset.offset = (uint16_t) -1U;
	memcpy(insn->data, &ref_offset, sizeof(ref_offset));
	/* reloc_offset points to struct load_op */
	reloc_offset_u32 = bytecode_get_len(&ctx->bytecode->b);
	if (reloc_offset_u32 > LTTNG_FILTER_MAX_LEN - 1) {
		ret = -EINVAL;
		goto end;
	}
	reloc_offset = (uint16_t) reloc_offset_u32;
	ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
	if (ret) {
		goto end;
	}
	/* append reloc */
	ret = bytecode_push(&ctx->bytecode_reloc, &reloc_offset, 1, sizeof(reloc_offset));
	if (ret) {
		goto end;
	}
	ret = bytecode_push(&ctx->bytecode_reloc, symbol, 1, strlen(symbol) + 1);
	if (ret) {
		goto end;
	}
	ret = 1; /* legacy */
end:
	free(insn);
	free(symbol);
	return ret;
}

static int visit_node_load_expression(struct filter_parser_ctx *ctx, const struct ir_op *node)
{
	struct ir_load_expression *exp;
	struct ir_load_expression_op *op;
	int ret;

	exp = node->u.load.u.expression;
	if (!exp) {
		return -EINVAL;
	}
	op = exp->child;
	if (!op) {
		return -EINVAL;
	}

	/*
	 * TODO: if we remove legacy load for application contexts, we
	 * need to update session bytecode parser as well.
	 */
	ret = visit_node_load_expression_legacy(ctx, exp);
	if (ret < 0) {
		return ret;
	}
	if (ret > 0) {
		return 0; /* legacy */
	}

	for (; op != nullptr; op = op->next) {
		switch (op->type) {
		case IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT:
		{
			ret = bytecode_push_get_context_root(&ctx->bytecode);

			if (ret) {
				return ret;
			}

			break;
		}
		case IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT:
		{
			ret = bytecode_push_get_app_context_root(&ctx->bytecode);

			if (ret) {
				return ret;
			}

			break;
		}
		case IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT:
		{
			ret = bytecode_push_get_payload_root(&ctx->bytecode);

			if (ret) {
				return ret;
			}

			break;
		}
		case IR_LOAD_EXPRESSION_GET_SYMBOL:
		{
			ret = bytecode_push_get_symbol(
				&ctx->bytecode, &ctx->bytecode_reloc, op->u.symbol);

			if (ret) {
				return ret;
			}

			break;
		}
		case IR_LOAD_EXPRESSION_GET_INDEX:
		{
			ret = bytecode_push_get_index_u64(&ctx->bytecode, op->u.index);

			if (ret) {
				return ret;
			}

			break;
		}
		case IR_LOAD_EXPRESSION_LOAD_FIELD:
		{
			struct load_op *insn;
			const auto insn_len = sizeof(struct load_op);

			insn = (load_op *) calloc(insn_len, 1);
			if (!insn)
				return -ENOMEM;
			insn->op = BYTECODE_OP_LOAD_FIELD;
			ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
			free(insn);
			if (ret) {
				return ret;
			}
			break;
		}
		}
	}
	return 0;
}

static int visit_node_load(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	int ret;

	switch (node->data_type) {
	case IR_DATA_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown data type in %s\n", __func__);
		return -EINVAL;

	case IR_DATA_STRING:
	{
		struct load_op *insn;
		const auto insn_len =
			sizeof(struct load_op) + strlen(node->u.load.u.string.value) + 1;

		insn = (load_op *) calloc(insn_len, 1);
		if (!insn)
			return -ENOMEM;

		switch (node->u.load.u.string.type) {
		case IR_LOAD_STRING_TYPE_GLOB_STAR:
			/*
			 * We explicitly tell the interpreter here that
			 * this load is a full star globbing pattern so
			 * that the appropriate matching function can be
			 * called. Also, see comment below.
			 */
			insn->op = BYTECODE_OP_LOAD_STAR_GLOB_STRING;
			break;
		default:
			/*
			 * This is the "legacy" string, which includes
			 * star globbing patterns with a star only at
			 * the end. Both "plain" and "star at the end"
			 * literal strings are handled at the same place
			 * by the tracer's filter bytecode interpreter,
			 * whereas full star globbing patterns (stars
			 * can be anywhere in the string) is a special
			 * case.
			 */
			insn->op = BYTECODE_OP_LOAD_STRING;
			break;
		}

		strcpy(insn->data, node->u.load.u.string.value);
		ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
		free(insn);
		return ret;
	}
	case IR_DATA_NUMERIC:
	{
		struct load_op *insn;
		const auto insn_len = sizeof(struct load_op) + sizeof(struct literal_numeric);

		insn = (load_op *) calloc(insn_len, 1);
		if (!insn)
			return -ENOMEM;
		insn->op = BYTECODE_OP_LOAD_S64;
		memcpy(insn->data, &node->u.load.u.num, sizeof(int64_t));
		ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
		free(insn);
		return ret;
	}
	case IR_DATA_FLOAT:
	{
		struct load_op *insn;
		const auto insn_len = sizeof(struct load_op) + sizeof(struct literal_double);

		insn = (load_op *) calloc(insn_len, 1);
		if (!insn)
			return -ENOMEM;
		insn->op = BYTECODE_OP_LOAD_DOUBLE;
		memcpy(insn->data, &node->u.load.u.flt, sizeof(double));
		ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
		free(insn);
		return ret;
	}
	case IR_DATA_EXPRESSION:
		return visit_node_load_expression(ctx, node);
	}
}

static int visit_node_unary(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	int ret;
	struct unary_op insn;

	/* Visit child */
	ret = recursive_visit_gen_bytecode(ctx, node->u.unary.child);
	if (ret)
		return ret;

	/* Generate end of bytecode instruction */
	switch (node->u.unary.type) {
	case AST_UNARY_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown unary node type in %s\n", __func__);
		return -EINVAL;
	case AST_UNARY_PLUS:
		/* Nothing to do. */
		return 0;
	case AST_UNARY_MINUS:
		insn.op = BYTECODE_OP_UNARY_MINUS;
		return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
	case AST_UNARY_NOT:
		insn.op = BYTECODE_OP_UNARY_NOT;
		return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
	case AST_UNARY_BIT_NOT:
		insn.op = BYTECODE_OP_UNARY_BIT_NOT;
		return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
	}
}

/*
 * Binary comparator nesting is disallowed. This allows fitting into
 * only 2 registers.
 */
static int visit_node_binary(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	int ret;
	struct binary_op insn;

	/* Visit child */
	ret = recursive_visit_gen_bytecode(ctx, node->u.binary.left);
	if (ret)
		return ret;
	ret = recursive_visit_gen_bytecode(ctx, node->u.binary.right);
	if (ret)
		return ret;

	switch (node->u.binary.type) {
	case AST_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown unary node type in %s\n", __func__);
		return -EINVAL;

	case AST_OP_AND:
	case AST_OP_OR:
		fprintf(stderr, "[error] Unexpected logical node type in %s\n", __func__);
		return -EINVAL;

	case AST_OP_MUL:
		insn.op = BYTECODE_OP_MUL;
		break;
	case AST_OP_DIV:
		insn.op = BYTECODE_OP_DIV;
		break;
	case AST_OP_MOD:
		insn.op = BYTECODE_OP_MOD;
		break;
	case AST_OP_PLUS:
		insn.op = BYTECODE_OP_PLUS;
		break;
	case AST_OP_MINUS:
		insn.op = BYTECODE_OP_MINUS;
		break;
	case AST_OP_BIT_RSHIFT:
		insn.op = BYTECODE_OP_BIT_RSHIFT;
		break;
	case AST_OP_BIT_LSHIFT:
		insn.op = BYTECODE_OP_BIT_LSHIFT;
		break;
	case AST_OP_BIT_AND:
		insn.op = BYTECODE_OP_BIT_AND;
		break;
	case AST_OP_BIT_OR:
		insn.op = BYTECODE_OP_BIT_OR;
		break;
	case AST_OP_BIT_XOR:
		insn.op = BYTECODE_OP_BIT_XOR;
		break;

	case AST_OP_EQ:
		insn.op = BYTECODE_OP_EQ;
		break;
	case AST_OP_NE:
		insn.op = BYTECODE_OP_NE;
		break;
	case AST_OP_GT:
		insn.op = BYTECODE_OP_GT;
		break;
	case AST_OP_LT:
		insn.op = BYTECODE_OP_LT;
		break;
	case AST_OP_GE:
		insn.op = BYTECODE_OP_GE;
		break;
	case AST_OP_LE:
		insn.op = BYTECODE_OP_LE;
		break;
	}
	return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
}

/*
 * A logical op always return a s64 (1 or 0).
 */
static int visit_node_logical(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	int ret;
	struct logical_op insn;
	uint16_t skip_offset_loc;
	uint16_t target_loc;

	/* Visit left child */
	ret = recursive_visit_gen_bytecode(ctx, node->u.binary.left);
	if (ret)
		return ret;
	/* Cast to s64 if float or field ref */
	if ((node->u.binary.left->data_type == IR_DATA_FIELD_REF ||
	     node->u.binary.left->data_type == IR_DATA_GET_CONTEXT_REF ||
	     node->u.binary.left->data_type == IR_DATA_EXPRESSION) ||
	    node->u.binary.left->data_type == IR_DATA_FLOAT) {
		struct cast_op cast_insn;

		if (node->u.binary.left->data_type == IR_DATA_FIELD_REF ||
		    node->u.binary.left->data_type == IR_DATA_GET_CONTEXT_REF ||
		    node->u.binary.left->data_type == IR_DATA_EXPRESSION) {
			cast_insn.op = BYTECODE_OP_CAST_TO_S64;
		} else {
			cast_insn.op = BYTECODE_OP_CAST_DOUBLE_TO_S64;
		}
		ret = bytecode_push(&ctx->bytecode, &cast_insn, 1, sizeof(cast_insn));
		if (ret)
			return ret;
	}
	switch (node->u.logical.type) {
	default:
		fprintf(stderr, "[error] Unknown node type in %s\n", __func__);
		return -EINVAL;

	case AST_OP_AND:
		insn.op = BYTECODE_OP_AND;
		break;
	case AST_OP_OR:
		insn.op = BYTECODE_OP_OR;
		break;
	}
	insn.skip_offset = (uint16_t) -1UL; /* Temporary */
	ret = bytecode_push_logical(&ctx->bytecode, &insn, 1, sizeof(insn), &skip_offset_loc);
	if (ret)
		return ret;
	/* Visit right child */
	ret = recursive_visit_gen_bytecode(ctx, node->u.binary.right);
	if (ret)
		return ret;
	/* Cast to s64 if float or field ref */
	if ((node->u.binary.right->data_type == IR_DATA_FIELD_REF ||
	     node->u.binary.right->data_type == IR_DATA_GET_CONTEXT_REF ||
	     node->u.binary.right->data_type == IR_DATA_EXPRESSION) ||
	    node->u.binary.right->data_type == IR_DATA_FLOAT) {
		struct cast_op cast_insn;

		if (node->u.binary.right->data_type == IR_DATA_FIELD_REF ||
		    node->u.binary.right->data_type == IR_DATA_GET_CONTEXT_REF ||
		    node->u.binary.right->data_type == IR_DATA_EXPRESSION) {
			cast_insn.op = BYTECODE_OP_CAST_TO_S64;
		} else {
			cast_insn.op = BYTECODE_OP_CAST_DOUBLE_TO_S64;
		}
		ret = bytecode_push(&ctx->bytecode, &cast_insn, 1, sizeof(cast_insn));
		if (ret)
			return ret;
	}
	/* We now know where the logical op can skip. */
	target_loc = (uint16_t) bytecode_get_len(&ctx->bytecode->b);
	ret = bytecode_patch(&ctx->bytecode,
			     &target_loc, /* Offset to jump to */
			     skip_offset_loc, /* Where to patch */
			     sizeof(uint16_t));
	return ret;
}

/*
 * Postorder traversal of the tree. We need the children result before
 * we can evaluate the parent.
 */
static int recursive_visit_gen_bytecode(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	switch (node->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown node type in %s\n", __func__);
		return -EINVAL;

	case IR_OP_ROOT:
		return visit_node_root(ctx, node);
	case IR_OP_LOAD:
		return visit_node_load(ctx, node);
	case IR_OP_UNARY:
		return visit_node_unary(ctx, node);
	case IR_OP_BINARY:
		return visit_node_binary(ctx, node);
	case IR_OP_LOGICAL:
		return visit_node_logical(ctx, node);
	}
}

void filter_bytecode_free(struct filter_parser_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->bytecode) {
		free(ctx->bytecode);
		ctx->bytecode = nullptr;
	}

	if (ctx->bytecode_reloc) {
		free(ctx->bytecode_reloc);
		ctx->bytecode_reloc = nullptr;
	}
}

int filter_visitor_bytecode_generate(struct filter_parser_ctx *ctx)
{
	int ret;

	ret = bytecode_init(&ctx->bytecode);
	if (ret)
		return ret;
	ret = bytecode_init(&ctx->bytecode_reloc);
	if (ret)
		goto error;
	ret = recursive_visit_gen_bytecode(ctx, ctx->ir_root);
	if (ret)
		goto error;

	/* Finally, append symbol table to bytecode */
	ctx->bytecode->b.reloc_table_offset = bytecode_get_len(&ctx->bytecode->b);
	return bytecode_push(&ctx->bytecode,
			     ctx->bytecode_reloc->b.data,
			     1,
			     bytecode_get_len(&ctx->bytecode_reloc->b));

error:
	filter_bytecode_free(ctx);
	return ret;
}
