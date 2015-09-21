/*
 * filter-visitor-set-parent.c
 *
 * LTTng filter set parent visitor
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

#include <common/macros.h>

static
int update_child(struct filter_node *parent,
		struct filter_node *old_child,
		struct filter_node *new_child)
{
	if (!parent) {
		fprintf(stderr, "[error] %s: NULL parent\n", __func__);
		return -EINVAL;
	}

	switch (parent->type) {
	case NODE_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown node type\n", __func__);
		return -EINVAL;
	case NODE_ROOT:
		assert(parent->u.root.child == old_child);
		parent->u.root.child = new_child;
		break;
	case NODE_EXPRESSION:
		assert(parent->u.expression.type == AST_EXP_NESTED);
		assert(parent->u.expression.u.child == old_child);
		parent->u.expression.u.child = new_child;
		break;
	case NODE_OP:
		assert(parent->u.op.lchild == old_child ||
			parent->u.op.rchild == old_child);
		if (parent->u.op.lchild == old_child)
			parent->u.op.lchild = new_child;
		else
			parent->u.op.rchild = new_child;
		break;
	case NODE_UNARY_OP:
		assert(parent->u.unary_op.child == old_child);
		parent->u.unary_op.child = new_child;
		break;
	}
	return 0;
}

static
int recursive_visit_set_parent(struct filter_node *node,
			struct filter_node *parent)
{
	int ret;

	if (!node) {
		fprintf(stderr, "[error] %s: NULL child\n", __func__);
		return -EINVAL;
	}
	node->parent = parent;
	switch (node->type) {
	case NODE_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown node type\n", __func__);
		return -EINVAL;
	case NODE_ROOT:
		assert(parent == NULL);
		return recursive_visit_set_parent(node->u.root.child, node);
	case NODE_EXPRESSION:
		switch (node->u.expression.type) {
		case AST_EXP_UNKNOWN:
		default:
			fprintf(stderr, "[error] %s: unknown expression type\n", __func__);
			return -EINVAL;
		case AST_EXP_NESTED:
			return recursive_visit_set_parent(node->u.expression.u.child, node);
		case AST_EXP_IDENTIFIER:	/* fall-through */
		case AST_EXP_GLOBAL_IDENTIFIER:
			{
				struct filter_node *orig_node = node;

				while (node->u.expression.prev) {
					struct filter_node *prev;

					prev = node->u.expression.prev;
					if (prev->type != NODE_EXPRESSION ||
						(prev->u.expression.type != AST_EXP_IDENTIFIER
						&& prev->u.expression.type != AST_EXP_GLOBAL_IDENTIFIER)) {
						fprintf(stderr, "[error] %s: expecting identifier before link\n", __func__);
						return -EINVAL;
					}

					prev->u.expression.next = node;
					prev->u.expression.pre_op =
						node->u.expression.post_op;
					prev->parent = node->parent;
					node = prev;
				}
				/* Set first child as forward */
				ret = update_child(parent, orig_node, node);
				if (ret)
					return ret;
			}
		case AST_EXP_CONSTANT:
		case AST_EXP_FLOAT_CONSTANT:
		case AST_EXP_STRING:
			break;
		}
		break;
	case NODE_OP:
		ret = recursive_visit_set_parent(node->u.op.lchild, node);
		if (ret)
			return ret;
		return recursive_visit_set_parent(node->u.op.rchild, node);
	case NODE_UNARY_OP:
		return recursive_visit_set_parent(node->u.unary_op.child, node);
	}
	return 0;
}

LTTNG_HIDDEN
int filter_visitor_set_parent(struct filter_parser_ctx *ctx)
{
	return recursive_visit_set_parent(&ctx->ast->root, NULL);
}
