/*
 * filter-visitor-ir-check-binary-comparator.c
 *
 * LTTng filter IR check binary comparator
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

static
int check_bin_comparator(struct ir_op *node)
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

		if (node->u.binary.left->data_type == IR_DATA_STRING
				|| node->u.binary.right->data_type
					== IR_DATA_STRING) {
			if (node->u.binary.type != AST_OP_EQ
					&& node->u.binary.type != AST_OP_NE) {
				fprintf(stderr, "[error] Only '==' and '!=' comparators are allowed for strings\n");
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
