#ifndef _FILTER_BYTECODE_H
#define _FILTER_BYTECODE_H

/*
 * filter-bytecode.h
 *
 * LTTng filter bytecode
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

#include <common/sessiond-comm/sessiond-comm.h>

#include "filter-ast.h"

/*
 * offsets are absolute from start of bytecode.
 */

struct field_ref {
	/* Initially, symbol offset. After link, field offset. */
	uint16_t offset;
} __attribute__((packed));

struct literal_numeric {
	int64_t v;
} __attribute__((packed));

struct literal_double {
	double v;
} __attribute__((packed));

struct literal_string {
	char string[0];
} __attribute__((packed));

enum filter_op {
	FILTER_OP_UNKNOWN = 0,

	FILTER_OP_RETURN,

	/* binary */
	FILTER_OP_MUL,
	FILTER_OP_DIV,
	FILTER_OP_MOD,
	FILTER_OP_PLUS,
	FILTER_OP_MINUS,
	FILTER_OP_RSHIFT,
	FILTER_OP_LSHIFT,
	FILTER_OP_BIN_AND,
	FILTER_OP_BIN_OR,
	FILTER_OP_BIN_XOR,

	/* binary comparators */
	FILTER_OP_EQ,
	FILTER_OP_NE,
	FILTER_OP_GT,
	FILTER_OP_LT,
	FILTER_OP_GE,
	FILTER_OP_LE,

	/* string binary comparator */
	FILTER_OP_EQ_STRING,
	FILTER_OP_NE_STRING,
	FILTER_OP_GT_STRING,
	FILTER_OP_LT_STRING,
	FILTER_OP_GE_STRING,
	FILTER_OP_LE_STRING,

	/* s64 binary comparator */
	FILTER_OP_EQ_S64,
	FILTER_OP_NE_S64,
	FILTER_OP_GT_S64,
	FILTER_OP_LT_S64,
	FILTER_OP_GE_S64,
	FILTER_OP_LE_S64,

	/* double binary comparator */
	FILTER_OP_EQ_DOUBLE,
	FILTER_OP_NE_DOUBLE,
	FILTER_OP_GT_DOUBLE,
	FILTER_OP_LT_DOUBLE,
	FILTER_OP_GE_DOUBLE,
	FILTER_OP_LE_DOUBLE,

	/* Mixed S64-double binary comparators */
	FILTER_OP_EQ_DOUBLE_S64,
	FILTER_OP_NE_DOUBLE_S64,
	FILTER_OP_GT_DOUBLE_S64,
	FILTER_OP_LT_DOUBLE_S64,
	FILTER_OP_GE_DOUBLE_S64,
	FILTER_OP_LE_DOUBLE_S64,

	FILTER_OP_EQ_S64_DOUBLE,
	FILTER_OP_NE_S64_DOUBLE,
	FILTER_OP_GT_S64_DOUBLE,
	FILTER_OP_LT_S64_DOUBLE,
	FILTER_OP_GE_S64_DOUBLE,
	FILTER_OP_LE_S64_DOUBLE,

	/* unary */
	FILTER_OP_UNARY_PLUS,
	FILTER_OP_UNARY_MINUS,
	FILTER_OP_UNARY_NOT,
	FILTER_OP_UNARY_PLUS_S64,
	FILTER_OP_UNARY_MINUS_S64,
	FILTER_OP_UNARY_NOT_S64,
	FILTER_OP_UNARY_PLUS_DOUBLE,
	FILTER_OP_UNARY_MINUS_DOUBLE,
	FILTER_OP_UNARY_NOT_DOUBLE,

	/* logical */
	FILTER_OP_AND,
	FILTER_OP_OR,

	/* load */
	FILTER_OP_LOAD_FIELD_REF,
	FILTER_OP_LOAD_FIELD_REF_STRING,
	FILTER_OP_LOAD_FIELD_REF_SEQUENCE,
	FILTER_OP_LOAD_FIELD_REF_S64,
	FILTER_OP_LOAD_FIELD_REF_DOUBLE,

	FILTER_OP_LOAD_STRING,
	FILTER_OP_LOAD_S64,
	FILTER_OP_LOAD_DOUBLE,

	/* cast */
	FILTER_OP_CAST_TO_S64,
	FILTER_OP_CAST_DOUBLE_TO_S64,
	FILTER_OP_CAST_NOP,

	NR_FILTER_OPS,
};

typedef uint8_t filter_opcode_t;

struct load_op {
	filter_opcode_t op;
	char data[0];
	/* data to load. Size known by enum filter_opcode and null-term char. */
} __attribute__((packed));

struct binary_op {
	filter_opcode_t op;
} __attribute__((packed));

struct unary_op {
	filter_opcode_t op;
} __attribute__((packed));

/* skip_offset is absolute from start of bytecode */
struct logical_op {
	filter_opcode_t op;
	uint16_t skip_offset;	/* bytecode insn, if skip second test */
} __attribute__((packed));

struct cast_op {
	filter_opcode_t op;
} __attribute__((packed));

struct return_op {
	filter_opcode_t op;
} __attribute__((packed));

struct lttng_filter_bytecode_alloc {
	uint32_t alloc_len;
	struct lttng_filter_bytecode b;
};

static inline
unsigned int bytecode_get_len(struct lttng_filter_bytecode *bytecode)
{
	return bytecode->len;
}

#endif /* _FILTER_BYTECODE_H */
