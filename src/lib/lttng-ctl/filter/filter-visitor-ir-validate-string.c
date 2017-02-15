/*
 * filter-visitor-ir-validate-string.c
 *
 * LTTng filter IR validate string
 *
 * Copyright 2014 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <common/macros.h>

#include "filter-ast.h"
#include "filter-parser.h"
#include "filter-ir.h"

enum parse_char_result {
	PARSE_CHAR_UNKNOWN = -2,
	PARSE_CHAR_WILDCARD = -1,
	PARSE_CHAR_NORMAL = 0,
};

static
enum parse_char_result parse_char(const char **p)
{
	switch (**p) {
	case '\\':
		(*p)++;
		switch (**p) {
		case '\\':
		case '*':
			return PARSE_CHAR_NORMAL;
		default:
			return PARSE_CHAR_UNKNOWN;
		}
	case '*':
		return PARSE_CHAR_WILDCARD;
	default:
		return PARSE_CHAR_NORMAL;
	}
}

static
int validate_string(struct ir_op *node)
{
	switch (node->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown op type\n", __func__);
		return -EINVAL;

	case IR_OP_ROOT:
		return validate_string(node->u.root.child);
	case IR_OP_LOAD:
	{
		int ret = 0;

		if (node->data_type == IR_DATA_STRING) {
			const char *str;

			assert(node->u.load.u.string.value);
			str = node->u.load.u.string.value;

			for (;;) {
				enum parse_char_result res;

				if (!(*str)) {
					break;
				}

				res = parse_char(&str);
				str++;

				switch (res) {
				case PARSE_CHAR_UNKNOWN:
					ret = -EINVAL;
					fprintf(stderr,
						"Unsupported escape character detected.\n");
					goto end_load;
				case PARSE_CHAR_NORMAL:
				default:
					break;
				}
			}
		}
end_load:
		return ret;
	}
	case IR_OP_UNARY:
		return validate_string(node->u.unary.child);
	case IR_OP_BINARY:
	{
		int ret = validate_string(node->u.binary.left);

		if (ret)
			return ret;
		return validate_string(node->u.binary.right);
	}
	case IR_OP_LOGICAL:
	{
		int ret;

		ret = validate_string(node->u.logical.left);
		if (ret)
			return ret;
		return validate_string(node->u.logical.right);
	}
	}
}

LTTNG_HIDDEN
int filter_visitor_ir_validate_string(struct filter_parser_ctx *ctx)
{
	return validate_string(ctx->ir_root);
}
