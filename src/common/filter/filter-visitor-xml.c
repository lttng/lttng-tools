/*
 * filter-visitor-xml.c
 *
 * LTTng filter XML pretty printer visitor
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

#include <common/macros.h>

#define fprintf_dbg(fd, fmt, args...)	fprintf(fd, "%s: " fmt, __func__, ## args)

static
int recursive_visit_print(struct filter_node *node, FILE *stream, int indent);

static
void print_tabs(FILE *fd, int depth)
{
	int i;

	for (i = 0; i < depth; i++)
		fprintf(fd, "\t");
}

static
int recursive_visit_print_expression(struct filter_node *node,
		FILE *stream, int indent)
{
	struct filter_node *iter_node;

	if (!node) {
		fprintf(stderr, "[error] %s: NULL child\n", __func__);
		return -EINVAL;
	}
	switch (node->u.expression.type) {
	case AST_EXP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown expression\n", __func__);
		return -EINVAL;
	case AST_EXP_STRING:
		print_tabs(stream, indent);
		fprintf(stream, "<string value=\"%s\"/>\n",
			node->u.expression.u.string);
		break;
	case AST_EXP_CONSTANT:
		print_tabs(stream, indent);
		fprintf(stream, "<constant value=\"%" PRIu64 "\"/>\n",
			node->u.expression.u.constant);
		break;
	case AST_EXP_FLOAT_CONSTANT:
		print_tabs(stream, indent);
		fprintf(stream, "<float_constant value=\"%lg\"/>\n",
			node->u.expression.u.float_constant);
		break;
	case AST_EXP_IDENTIFIER:		/* fall-through */
	case AST_EXP_GLOBAL_IDENTIFIER:
		print_tabs(stream, indent);
		fprintf(stream, "<%s value=\"%s\"/>\n",
			node->u.expression.type == AST_EXP_IDENTIFIER ?
				"identifier" : "global_identifier",
			node->u.expression.u.identifier);
		iter_node = node->u.expression.next;
		while (iter_node) {
			print_tabs(stream, indent);
			fprintf(stream, "<bracket>\n");
			if (recursive_visit_print_expression(iter_node,
					stream, indent + 1)) {
				return -EINVAL;
			}
			print_tabs(stream, indent);
			fprintf(stream, "</bracket>\n");
			iter_node = iter_node->u.expression.next;

		}
		break;
	case AST_EXP_NESTED:
		return recursive_visit_print(node->u.expression.u.child,
				stream, indent + 1);
	}
	return 0;
}


static
int recursive_visit_print(struct filter_node *node, FILE *stream, int indent)
{
	int ret;

	if (!node) {
		fprintf(stderr, "[error] %s: NULL child\n", __func__);
		return -EINVAL;
	}
	switch (node->type) {
	case NODE_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown node type\n", __func__);
		return -EINVAL;
	case NODE_ROOT:
		print_tabs(stream, indent);
		fprintf(stream, "<root>\n");
		ret = recursive_visit_print(node->u.root.child, stream,
					indent + 1);
		print_tabs(stream, indent);
		fprintf(stream, "</root>\n");
		return ret;
	case NODE_EXPRESSION:
		print_tabs(stream, indent);
		fprintf(stream, "<expression>\n");
		ret = recursive_visit_print_expression(node, stream,
					indent + 1);
		print_tabs(stream, indent);
		fprintf(stream, "</expression>\n");
		return ret;
	case NODE_OP:
		print_tabs(stream, indent);
		fprintf(stream, "<op type=");
		switch (node->u.op.type) {
		case AST_OP_UNKNOWN:
		default:
			fprintf(stderr, "[error] %s: unknown op\n", __func__);
			return -EINVAL;
		case AST_OP_MUL:
			fprintf(stream, "\"*\"");
			break;
		case AST_OP_DIV:
			fprintf(stream, "\"/\"");
			break;
		case AST_OP_MOD:
			fprintf(stream, "\"%%\"");
			break;
		case AST_OP_PLUS:
			fprintf(stream, "\"+\"");
			break;
		case AST_OP_MINUS:
			fprintf(stream, "\"-\"");
			break;
		case AST_OP_BIT_RSHIFT:
			fprintf(stream, "\">>\"");
			break;
		case AST_OP_BIT_LSHIFT:
			fprintf(stream, "\"<<\"");
			break;
		case AST_OP_AND:
			fprintf(stream, "\"&&\"");
			break;
		case AST_OP_OR:
			fprintf(stream, "\"||\"");
			break;
		case AST_OP_BIT_AND:
			fprintf(stream, "\"&\"");
			break;
		case AST_OP_BIT_OR:
			fprintf(stream, "\"|\"");
			break;
		case AST_OP_BIT_XOR:
			fprintf(stream, "\"^\"");
			break;

		case AST_OP_EQ:
			fprintf(stream, "\"==\"");
			break;
		case AST_OP_NE:
			fprintf(stream, "\"!=\"");
			break;
		case AST_OP_GT:
			fprintf(stream, "\">\"");
			break;
		case AST_OP_LT:
			fprintf(stream, "\"<\"");
			break;
		case AST_OP_GE:
			fprintf(stream, "\">=\"");
			break;
		case AST_OP_LE:
			fprintf(stream, "\"<=\"");
			break;
		}
		fprintf(stream, ">\n");
		ret = recursive_visit_print(node->u.op.lchild,
					stream, indent + 1);
		if (ret)
			return ret;
		ret = recursive_visit_print(node->u.op.rchild,
					stream, indent + 1);
		if (ret)
			return ret;
		print_tabs(stream, indent);
		fprintf(stream, "</op>\n");
		return ret;
	case NODE_UNARY_OP:
		print_tabs(stream, indent);
		fprintf(stream, "<unary_op type=");
		switch (node->u.unary_op.type) {
		case AST_UNARY_UNKNOWN:
		default:
			fprintf(stderr, "[error] %s: unknown unary_op\n", __func__);
			return -EINVAL;
		case AST_UNARY_PLUS:
			fprintf(stream, "\"+\"");
			break;
		case AST_UNARY_MINUS:
			fprintf(stream, "\"-\"");
			break;
		case AST_UNARY_NOT:
			fprintf(stream, "\"!\"");
			break;
		case AST_UNARY_BIT_NOT:
			fprintf(stream, "\"~\"");
			break;
		}
		fprintf(stream, ">\n");
		ret = recursive_visit_print(node->u.unary_op.child,
					stream, indent + 1);
		print_tabs(stream, indent);
		fprintf(stream, "</unary_op>\n");
		return ret;
	}
	return 0;
}

LTTNG_HIDDEN
int filter_visitor_print_xml(struct filter_parser_ctx *ctx, FILE *stream,
			int indent)
{
	return recursive_visit_print(&ctx->ast->root, stream, indent);
}
