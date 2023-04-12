#ifndef _FILTER_IR_H
#define _FILTER_IR_H

/*
 * filter-ir.h
 *
 * LTTng filter ir
 *
 * Copyright 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "filter-ast.hpp"

#include <cstdlib>

enum ir_op_signedness {
	IR_SIGN_UNKNOWN = 0,
	IR_SIGNED,
	IR_UNSIGNED,
	IR_SIGN_DYN, /* signedness determined dynamically */
};

enum ir_data_type {
	IR_DATA_UNKNOWN = 0,
	IR_DATA_STRING,
	IR_DATA_NUMERIC, /* numeric and boolean */
	IR_DATA_FLOAT,
	IR_DATA_FIELD_REF,
	IR_DATA_GET_CONTEXT_REF,
	IR_DATA_EXPRESSION,
};

static inline const char *ir_data_type_str(enum ir_data_type type)
{
	switch (type) {
	case IR_DATA_UNKNOWN:
		return "IR_DATA_UNKNOWN";
	case IR_DATA_STRING:
		return "IR_DATA_STRING";
	case IR_DATA_NUMERIC:
		return "IR_DATA_NUMERIC";
	case IR_DATA_FLOAT:
		return "IR_DATA_FLOAT";
	case IR_DATA_FIELD_REF:
		return "IR_DATA_FIELD_REF";
	case IR_DATA_GET_CONTEXT_REF:
		return "IR_DATA_GET_CONTEXT_REF";
	case IR_DATA_EXPRESSION:
		return "IR_DATA_EXPRESSION";
	default:
		abort();
	}
}

enum ir_op_type {
	IR_OP_UNKNOWN = 0,
	IR_OP_ROOT,
	IR_OP_LOAD,
	IR_OP_UNARY,
	IR_OP_BINARY,
	IR_OP_LOGICAL,
};

static inline const char *ir_op_type_str(enum ir_op_type type)
{
	switch (type) {
	case IR_OP_UNKNOWN:
		return "IR_OP_UNKNOWN";
	case IR_OP_ROOT:
		return "IR_OP_ROOT";
	case IR_OP_LOAD:
		return "IR_OP_LOAD";
	case IR_OP_UNARY:
		return "IR_OP_UNARY";
	case IR_OP_BINARY:
		return "IR_OP_BINARY";
	case IR_OP_LOGICAL:
		return "IR_OP_LOGICAL";
	default:
		abort();
	}
}

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

enum ir_load_expression_type {
	IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT,
	IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT,
	IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT,
	IR_LOAD_EXPRESSION_GET_SYMBOL,
	IR_LOAD_EXPRESSION_GET_INDEX,
	IR_LOAD_EXPRESSION_LOAD_FIELD,
};

static inline const char *ir_load_expression_type_str(enum ir_load_expression_type type)
{
	switch (type) {
	case IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT:
		return "IR_LOAD_EXPRESSION_GET_CONTEXT_ROOT";
	case IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT:
		return "IR_LOAD_EXPRESSION_GET_APP_CONTEXT_ROOT";
	case IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT:
		return "IR_LOAD_EXPRESSION_GET_PAYLOAD_ROOT";
	case IR_LOAD_EXPRESSION_GET_SYMBOL:
		return "IR_LOAD_EXPRESSION_GET_SYMBOL";
	case IR_LOAD_EXPRESSION_GET_INDEX:
		return "IR_LOAD_EXPRESSION_GET_INDEX";
	case IR_LOAD_EXPRESSION_LOAD_FIELD:
		return "IR_LOAD_EXPRESSION_LOAD_FIELD";
	default:
		abort();
	}
}

struct ir_load_expression_op {
	struct ir_load_expression_op *next;
	enum ir_load_expression_type type;
	union {
		char *symbol;
		uint64_t index;
	} u;
};

struct ir_load_expression {
	struct ir_load_expression_op *child;
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
		struct ir_load_expression *expression;
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
