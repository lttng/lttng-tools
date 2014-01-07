/*
 * filter-visitor-ir-check-binary-op-nesting.c
 *
 * LTTng filter IR check binary op nesting
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

static
int check_bin_op_nesting_recursive(struct ir_op *node, int nesting)
{
	switch (node->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown op type\n", __func__);
		return -EINVAL;

	case IR_OP_ROOT:
		return check_bin_op_nesting_recursive(node->u.root.child,
				nesting);
	case IR_OP_LOAD:
		return 0;
	case IR_OP_UNARY:
		return check_bin_op_nesting_recursive(node->u.unary.child,
				nesting);
	case IR_OP_BINARY:
	{
		int ret;

		if (nesting > 0) {
			fprintf(stderr, "[error] Nesting of binary operators is not allowed, except for logical operators.\n");
			return -EINVAL;
		}
		ret = check_bin_op_nesting_recursive(node->u.binary.left,
				nesting + 1);
		if (ret)
			return ret;
		return check_bin_op_nesting_recursive(node->u.binary.right,
				nesting + 1);
	}
	case IR_OP_LOGICAL:
	{
		int ret;

		ret = check_bin_op_nesting_recursive(node->u.logical.left,
				nesting);
		if (ret)
			return ret;
		return check_bin_op_nesting_recursive(node->u.logical.right,
				nesting);
	}
	}
}

LTTNG_HIDDEN
int filter_visitor_ir_check_binary_op_nesting(struct filter_parser_ctx *ctx)
{
	return check_bin_op_nesting_recursive(ctx->ir_root, 0);
}
