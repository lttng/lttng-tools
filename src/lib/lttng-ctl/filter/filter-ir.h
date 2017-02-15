#ifndef _FILTER_IR_H
#define _FILTER_IR_H

/*
 * filter-ir.h
 *
 * LTTng filter ir
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

#include "filter-ast.h"

enum ir_op_signedness {
	IR_SIGN_UNKNOWN = 0,
	IR_SIGNED,
	IR_UNSIGNED,
	IR_SIGN_DYN,		/* signedness determined dynamically */
};

enum ir_data_type {
	IR_DATA_UNKNOWN = 0,
	IR_DATA_STRING,
	IR_DATA_NUMERIC,	/* numeric and boolean */
	IR_DATA_FLOAT,
	IR_DATA_FIELD_REF,
	IR_DATA_GET_CONTEXT_REF,
};

enum ir_op_type {
	IR_OP_UNKNOWN = 0,
	IR_OP_ROOT,
	IR_OP_LOAD,
	IR_OP_UNARY,
	IR_OP_BINARY,
	IR_OP_LOGICAL,
};

/* left or right child */
enum ir_side {
	IR_SIDE_UNKNOWN = 0,
	IR_LEFT,
	IR_RIGHT,
};

enum ir_load_string_type {
	/* Plain, no globbing at all: `hello world`. */
	IR_LOAD_STRING_TYPE_PLAIN = 0,

	/* Star at the end only: `hello *`. */
	IR_LOAD_STRING_TYPE_GLOB_STAR_END,

	/* At least one star, anywhere, but not at the end only: `he*wor*`. */
	IR_LOAD_STRING_TYPE_GLOB_STAR,
};

struct ir_op_root {
	struct ir_op *child;
};

struct ir_op_load {
	union {
		struct {
			enum ir_load_string_type type;
			char *value;
		} string;
		int64_t num;
		double flt;
		char *ref;
	} u;
};

struct ir_op_unary {
	enum unary_op_type type;
	struct ir_op *child;
};

struct ir_op_binary {
	enum op_type type;
	struct ir_op *left;
	struct ir_op *right;
};

struct ir_op_logical {
	enum op_type type;
	struct ir_op *left;
	struct ir_op *right;
};

struct ir_op {
	/* common to all ops */
	enum ir_op_type op;
	enum ir_data_type data_type;
	enum ir_op_signedness signedness;
	enum ir_side side;

	union {
		struct ir_op_root root;
		struct ir_op_load load;
		struct ir_op_unary unary;
		struct ir_op_binary binary;
		struct ir_op_logical logical;
	} u;
};

#endif /* _FILTER_IR_H */
