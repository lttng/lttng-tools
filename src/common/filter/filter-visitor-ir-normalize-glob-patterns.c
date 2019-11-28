/*
 * filter-visitor-ir-normalize-glob-patterns.c
 *
 * LTTng filter IR normalize string
 *
 * Copyright 2017 Philippe Proulx <pproulx@efficios.com>
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

#include <common/macros.h>
#include <common/string-utils/string-utils.h>

#include "filter-ast.h"
#include "filter-parser.h"
#include "filter-ir.h"

static
int normalize_glob_patterns(struct ir_op *node)
{
	switch (node->op) {
	case IR_OP_UNKNOWN:
	default:
		fprintf(stderr, "[error] %s: unknown op type\n", __func__);
		return -EINVAL;

	case IR_OP_ROOT:
		return normalize_glob_patterns(node->u.root.child);
	case IR_OP_LOAD:
	{
		if (node->data_type == IR_DATA_STRING) {
			enum ir_load_string_type type =
				node->u.load.u.string.type;
			if (type == IR_LOAD_STRING_TYPE_GLOB_STAR_END ||
					type == IR_LOAD_STRING_TYPE_GLOB_STAR) {
				assert(node->u.load.u.string.value);
				strutils_normalize_star_glob_pattern(
					node->u.load.u.string.value);
			}
		}

		return 0;
	}
	case IR_OP_UNARY:
		return normalize_glob_patterns(node->u.unary.child);
	case IR_OP_BINARY:
	{
		int ret = normalize_glob_patterns(node->u.binary.left);

		if (ret)
			return ret;
		return normalize_glob_patterns(node->u.binary.right);
	}
	case IR_OP_LOGICAL:
	{
		int ret;

		ret = normalize_glob_patterns(node->u.logical.left);
		if (ret)
			return ret;
		return normalize_glob_patterns(node->u.logical.right);
	}
	}
}

/*
 * This function normalizes all the globbing literal strings with
 * utils_normalize_glob_pattern(). See the documentation of
 * utils_normalize_glob_pattern() for more details.
 */
LTTNG_HIDDEN
int filter_visitor_ir_normalize_glob_patterns(struct filter_parser_ctx *ctx)
{
	return normalize_glob_patterns(ctx->ir_root);
}
