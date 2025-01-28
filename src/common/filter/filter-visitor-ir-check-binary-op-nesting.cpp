/*
 * filter-visitor-ir-check-binary-op-nesting.c
 *
 * LTTng filter IR check binary op nesting
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
#include <common/macros.hpp>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int check_bin_op_nesting_recursive(struct ir_op *node, int nesting)
{
	switch (node->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown op type\n", __func__);
		return -EINVAL;

	case IR_OP_ROOT:
		return check_bin_op_nesting_recursive(node->u.root.child, nesting);
	case IR_OP_LOAD:
		return 0;
	case IR_OP_UNARY:
		return check_bin_op_nesting_recursive(node->u.unary.child, nesting);
	case IR_OP_BINARY:
	{
		int ret;

		ret = check_bin_op_nesting_recursive(node->u.binary.left, nesting + 1);
		if (ret)
			return ret;
		return check_bin_op_nesting_recursive(node->u.binary.right, nesting + 1);
	}
	case IR_OP_LOGICAL:
	{
		int ret;

		ret = check_bin_op_nesting_recursive(node->u.logical.left, nesting);
		if (ret)
			return ret;
		return check_bin_op_nesting_recursive(node->u.logical.right, nesting);
	}
	}
}

int filter_visitor_ir_check_binary_op_nesting(struct filter_parser_ctx *ctx)
{
	return check_bin_op_nesting_recursive(ctx->ir_root, 0);
}
