/*
 * filter-visitor-generate-bytecode.c
 *
 * LTTng filter bytecode generation
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <common/align.h>
#include <common/compat/string.h>

#include "filter-bytecode.h"
#include "filter-ir.h"
#include "filter-ast.h"

#include <common/macros.h>

#ifndef max_t
#define max_t(type, a, b)	((type) ((a) > (b) ? (a) : (b)))
#endif

#define INIT_ALLOC_SIZE		4

static
int recursive_visit_gen_bytecode(struct filter_parser_ctx *ctx,
		struct ir_op *node);

static inline int get_count_order(unsigned int count)
{
	int order;

	order = lttng_fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

static
int bytecode_init(struct lttng_filter_bytecode_alloc **fb)
{
	uint32_t alloc_len;

	alloc_len = sizeof(struct lttng_filter_bytecode_alloc) + INIT_ALLOC_SIZE;
	*fb = calloc(alloc_len, 1);
	if (!*fb) {
		return -ENOMEM;
	} else {
		(*fb)->alloc_len = alloc_len;
		return 0;
	}
}

static
int32_t bytecode_reserve(struct lttng_filter_bytecode_alloc **fb, uint32_t align, uint32_t len)
{
	int32_t ret;
	uint32_t padding = offset_align((*fb)->b.len, align);
	uint32_t new_len = (*fb)->b.len + padding + len;
	uint32_t new_alloc_len = sizeof(struct lttng_filter_bytecode_alloc) + new_len;
	uint32_t old_alloc_len = (*fb)->alloc_len;

	if (new_len > LTTNG_FILTER_MAX_LEN)
		return -EINVAL;

	if (new_alloc_len > old_alloc_len) {
		struct lttng_filter_bytecode_alloc *newptr;

		new_alloc_len =
			max_t(uint32_t, 1U << get_count_order(new_alloc_len), old_alloc_len << 1);
		newptr = realloc(*fb, new_alloc_len);
		if (!newptr)
			return -ENOMEM;
		*fb = newptr;
		/* We zero directly the memory from start of allocation. */
		memset(&((char *) *fb)[old_alloc_len], 0, new_alloc_len - old_alloc_len);
		(*fb)->alloc_len = new_alloc_len;
	}
	(*fb)->b.len += padding;
	ret = (*fb)->b.len;
	(*fb)->b.len += len;
	return ret;
}

static
int bytecode_push(struct lttng_filter_bytecode_alloc **fb, const void *data,
		uint32_t align, uint32_t len)
{
	int32_t offset;

	offset = bytecode_reserve(fb, align, len);
	if (offset < 0)
		return offset;
	memcpy(&(*fb)->b.data[offset], data, len);
	return 0;
}

static
int bytecode_push_logical(struct lttng_filter_bytecode_alloc **fb,
		struct logical_op *data,
		uint32_t align, uint32_t len,
		uint16_t *skip_offset)
{
	int32_t offset;

	offset = bytecode_reserve(fb, align, len);
	if (offset < 0)
		return offset;
	memcpy(&(*fb)->b.data[offset], data, len);
	*skip_offset =
		(void *) &((struct logical_op *) &(*fb)->b.data[offset])->skip_offset
			- (void *) &(*fb)->b.data[0];
	return 0;
}

static
int bytecode_patch(struct lttng_filter_bytecode_alloc **fb,
		const void *data,
		uint16_t offset,
		uint32_t len)
{
	if (offset >= (*fb)->b.len) {
		return -EINVAL;
	}
	memcpy(&(*fb)->b.data[offset], data, len);
	return 0;
}

static
int visit_node_root(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	int ret;
	struct return_op insn;

	/* Visit child */
	ret = recursive_visit_gen_bytecode(ctx, node->u.root.child);
	if (ret)
		return ret;

	/* Generate end of bytecode instruction */
	insn.op = FILTER_OP_RETURN;
	return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
}

static
int visit_node_load(struct filter_parser_ctx *ctx, struct ir_op *node)
{
	int ret;

	switch (node->data_type) {
	case IR_DATA_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown data type in %s\n",
			__func__);
		return -EINVAL;

	case IR_DATA_STRING:
	{
		struct load_op *insn;
		uint32_t insn_len = sizeof(struct load_op)
			+ strlen(node->u.load.u.string.value) + 1;

		insn = calloc(insn_len, 1);
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
			insn->op = FILTER_OP_LOAD_STAR_GLOB_STRING;
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
			insn->op = FILTER_OP_LOAD_STRING;
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
		uint32_t insn_len = sizeof(struct load_op)
			+ sizeof(struct literal_numeric);

		insn = calloc(insn_len, 1);
		if (!insn)
			return -ENOMEM;
		insn->op = FILTER_OP_LOAD_S64;
		memcpy(insn->data, &node->u.load.u.num, sizeof(int64_t));
		ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
		free(insn);
		return ret;
	}
	case IR_DATA_FLOAT:
	{
		struct load_op *insn;
		uint32_t insn_len = sizeof(struct load_op)
			+ sizeof(struct literal_double);

		insn = calloc(insn_len, 1);
		if (!insn)
			return -ENOMEM;
		insn->op = FILTER_OP_LOAD_DOUBLE;
		memcpy(insn->data, &node->u.load.u.flt, sizeof(double));
		ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
		free(insn);
		return ret;
	}
	case IR_DATA_FIELD_REF:	/* fall-through */
	case IR_DATA_GET_CONTEXT_REF:
	{
		struct load_op *insn;
		uint32_t insn_len = sizeof(struct load_op)
			+ sizeof(struct field_ref);
		struct field_ref ref_offset;
		uint32_t reloc_offset_u32;
		uint16_t reloc_offset;

		insn = calloc(insn_len, 1);
		if (!insn)
			return -ENOMEM;
		switch(node->data_type) {
		case IR_DATA_FIELD_REF:
			insn->op = FILTER_OP_LOAD_FIELD_REF;
			break;
		case IR_DATA_GET_CONTEXT_REF:
			insn->op = FILTER_OP_GET_CONTEXT_REF;
			break;
		default:
			free(insn);
			return -EINVAL;
		}
		ref_offset.offset = (uint16_t) -1U;
		memcpy(insn->data, &ref_offset, sizeof(ref_offset));
		/* reloc_offset points to struct load_op */
		reloc_offset_u32 = bytecode_get_len(&ctx->bytecode->b);
		if (reloc_offset_u32 > LTTNG_FILTER_MAX_LEN - 1) {
			free(insn);
			return -EINVAL;
		}
		reloc_offset = (uint16_t) reloc_offset_u32;
		ret = bytecode_push(&ctx->bytecode, insn, 1, insn_len);
		if (ret) {
			free(insn);
			return ret;
		}
		/* append reloc */
		ret = bytecode_push(&ctx->bytecode_reloc, &reloc_offset,
					1, sizeof(reloc_offset));
		if (ret) {
			free(insn);
			return ret;
		}
		ret = bytecode_push(&ctx->bytecode_reloc, node->u.load.u.ref,
					1, strlen(node->u.load.u.ref) + 1);
		free(insn);
		return ret;
	}
	}
}

static
int visit_node_unary(struct filter_parser_ctx *ctx, struct ir_op *node)
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
		fprintf(stderr, "[error] Unknown unary node type in %s\n",
			__func__);
		return -EINVAL;
	case AST_UNARY_PLUS:
		/* Nothing to do. */
		return 0;
	case AST_UNARY_MINUS:
		insn.op = FILTER_OP_UNARY_MINUS;
		return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
	case AST_UNARY_NOT:
		insn.op = FILTER_OP_UNARY_NOT;
		return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
	}
}

/*
 * Binary comparator nesting is disallowed. This allows fitting into
 * only 2 registers.
 */
static
int visit_node_binary(struct filter_parser_ctx *ctx, struct ir_op *node)
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
		fprintf(stderr, "[error] Unknown unary node type in %s\n",
			__func__);
		return -EINVAL;

	case AST_OP_AND:
	case AST_OP_OR:
		fprintf(stderr, "[error] Unexpected logical node type in %s\n",
			__func__);
		return -EINVAL;

	case AST_OP_MUL:
		insn.op = FILTER_OP_MUL;
		break;
	case AST_OP_DIV:
		insn.op = FILTER_OP_DIV;
		break;
	case AST_OP_MOD:
		insn.op = FILTER_OP_MOD;
		break;
	case AST_OP_PLUS:
		insn.op = FILTER_OP_PLUS;
		break;
	case AST_OP_MINUS:
		insn.op = FILTER_OP_MINUS;
		break;
	case AST_OP_RSHIFT:
		insn.op = FILTER_OP_RSHIFT;
		break;
	case AST_OP_LSHIFT:
		insn.op = FILTER_OP_LSHIFT;
		break;
	case AST_OP_BIN_AND:
		insn.op = FILTER_OP_BIN_AND;
		break;
	case AST_OP_BIN_OR:
		insn.op = FILTER_OP_BIN_OR;
		break;
	case AST_OP_BIN_XOR:
		insn.op = FILTER_OP_BIN_XOR;
		break;

	case AST_OP_EQ:
		insn.op = FILTER_OP_EQ;
		break;
	case AST_OP_NE:
		insn.op = FILTER_OP_NE;
		break;
	case AST_OP_GT:
		insn.op = FILTER_OP_GT;
		break;
	case AST_OP_LT:
		insn.op = FILTER_OP_LT;
		break;
	case AST_OP_GE:
		insn.op = FILTER_OP_GE;
		break;
	case AST_OP_LE:
		insn.op = FILTER_OP_LE;
		break;
	}
	return bytecode_push(&ctx->bytecode, &insn, 1, sizeof(insn));
}

/*
 * A logical op always return a s64 (1 or 0).
 */
static
int visit_node_logical(struct filter_parser_ctx *ctx, struct ir_op *node)
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
	if ((node->u.binary.left->data_type == IR_DATA_FIELD_REF
				|| node->u.binary.left->data_type == IR_DATA_GET_CONTEXT_REF)
			|| node->u.binary.left->data_type == IR_DATA_FLOAT) {
		struct cast_op cast_insn;

		if (node->u.binary.left->data_type == IR_DATA_FIELD_REF
				|| node->u.binary.left->data_type == IR_DATA_GET_CONTEXT_REF) {
			cast_insn.op = FILTER_OP_CAST_TO_S64;
		} else {
			cast_insn.op = FILTER_OP_CAST_DOUBLE_TO_S64;
		}
		ret = bytecode_push(&ctx->bytecode, &cast_insn,
					1, sizeof(cast_insn));
		if (ret)
			return ret;
	}
	switch (node->u.logical.type) {
	default:
		fprintf(stderr, "[error] Unknown node type in %s\n",
			__func__);
		return -EINVAL;

	case AST_OP_AND:
		insn.op = FILTER_OP_AND;
		break;
	case AST_OP_OR:
		insn.op = FILTER_OP_OR;
		break;
	}
	insn.skip_offset = (uint16_t) -1UL;	/* Temporary */
	ret = bytecode_push_logical(&ctx->bytecode, &insn, 1, sizeof(insn),
			&skip_offset_loc);
	if (ret)
		return ret;
	/* Visit right child */
	ret = recursive_visit_gen_bytecode(ctx, node->u.binary.right);
	if (ret)
		return ret;
	/* Cast to s64 if float or field ref */
	if ((node->u.binary.right->data_type == IR_DATA_FIELD_REF
				|| node->u.binary.right->data_type == IR_DATA_GET_CONTEXT_REF)
			|| node->u.binary.right->data_type == IR_DATA_FLOAT) {
		struct cast_op cast_insn;

		if (node->u.binary.right->data_type == IR_DATA_FIELD_REF
				|| node->u.binary.right->data_type == IR_DATA_GET_CONTEXT_REF) {
			cast_insn.op = FILTER_OP_CAST_TO_S64;
		} else {
			cast_insn.op = FILTER_OP_CAST_DOUBLE_TO_S64;
		}
		ret = bytecode_push(&ctx->bytecode, &cast_insn,
					1, sizeof(cast_insn));
		if (ret)
			return ret;
	}
	/* We now know where the logical op can skip. */
	target_loc = (uint16_t) bytecode_get_len(&ctx->bytecode->b);
	ret = bytecode_patch(&ctx->bytecode,
			&target_loc,			/* Offset to jump to */
			skip_offset_loc,		/* Where to patch */
			sizeof(uint16_t));
	return ret;
}

/*
 * Postorder traversal of the tree. We need the children result before
 * we can evaluate the parent.
 */
static
int recursive_visit_gen_bytecode(struct filter_parser_ctx *ctx,
		struct ir_op *node)
{
	switch (node->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] Unknown node type in %s\n",
			__func__);
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

LTTNG_HIDDEN
void filter_bytecode_free(struct filter_parser_ctx *ctx)
{
	if (!ctx) {
		return;
	}

	if (ctx->bytecode) {
		free(ctx->bytecode);
		ctx->bytecode = NULL;
	}

	if (ctx->bytecode_reloc) {
		free(ctx->bytecode_reloc);
		ctx->bytecode_reloc = NULL;
	}
}

LTTNG_HIDDEN
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
	return bytecode_push(&ctx->bytecode, ctx->bytecode_reloc->b.data,
			1, bytecode_get_len(&ctx->bytecode_reloc->b));

error:
	filter_bytecode_free(ctx);
	return ret;
}
