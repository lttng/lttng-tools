/*
 * filter-visitor-ir-check-binary-comparator.c
 *
 * LTTng filter IR check binary comparator
 *
 * SPDX-FileCopyrightText: 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "filter-ast.hpp"
#include "filter-ir.hpp"
#include "filter-parser.hpp"

#include <common/compat/errno.hpp>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int check_bin_comparator(struct ir_op *node)
{
	switch (node->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown op type\n", __func__);
		return -EINVAL;

	case IR_OP_ROOT:
		return check_bin_comparator(node->u.root.child);
	case IR_OP_LOAD:
		return 0;
	case IR_OP_UNARY:
		return check_bin_comparator(node->u.unary.child);
	case IR_OP_BINARY:
	{
		int ret;

		if (node->u.binary.left->data_type == IR_DATA_STRING ||
		    node->u.binary.right->data_type == IR_DATA_STRING) {
			if (node->u.binary.type != AST_OP_EQ && node->u.binary.type != AST_OP_NE) {
				fprintf(stderr,
					"[error] Only '==' and '!=' comparators are allowed for strings\n");
				return -EINVAL;
			}
		}

		ret = check_bin_comparator(node->u.binary.left);
		if (ret)
			return ret;
		return check_bin_comparator(node->u.binary.right);
	}
	case IR_OP_LOGICAL:
	{
		int ret;

		ret = check_bin_comparator(node->u.logical.left);
		if (ret)
			return ret;
		return check_bin_comparator(node->u.logical.right);
	}
	}
}

int filter_visitor_ir_check_binary_comparator(struct filter_parser_ctx *ctx)
{
	return check_bin_comparator(ctx->ir_root);
}
