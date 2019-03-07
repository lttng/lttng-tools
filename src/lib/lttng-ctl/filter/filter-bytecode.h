#ifndef _FILTER_BYTECODE_H
#define _FILTER_BYTECODE_H

/*
 * filter-bytecode.h
 *
 * LTTng filter bytecode
 *
 * Copyright 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/sessiond-comm/sessiond-comm.h>
#include <common/macros.h>

#include "filter-ast.h"

/*
 * offsets are absolute from start of bytecode.
 */

struct field_ref {
	/* Initially, symbol offset. After link, field offset. */
	uint16_t offset;
} LTTNG_PACKED;

struct get_symbol {
	/* Symbol offset. */
	uint16_t offset;
} LTTNG_PACKED;

struct get_index_u16 {
	uint16_t index;
} LTTNG_PACKED;

struct get_index_u64 {
	uint64_t index;
} LTTNG_PACKED;

struct literal_numeric {
	int64_t v;
} LTTNG_PACKED;

struct literal_double {
	double v;
} LTTNG_PACKED;

struct literal_string {
	char string[0];
} LTTNG_PACKED;

enum filter_op {
	FILTER_OP_UNKNOWN			= 0,

	FILTER_OP_RETURN			= 1,

	/* binary */
	FILTER_OP_MUL				= 2,
	FILTER_OP_DIV				= 3,
	FILTER_OP_MOD				= 4,
	FILTER_OP_PLUS				= 5,
	FILTER_OP_MINUS				= 6,
	FILTER_OP_BIT_RSHIFT			= 7,
	FILTER_OP_BIT_LSHIFT			= 8,
	FILTER_OP_BIT_AND			= 9,
	FILTER_OP_BIT_OR			= 10,
	FILTER_OP_BIT_XOR			= 11,

	/* binary comparators */
	FILTER_OP_EQ				= 12,
	FILTER_OP_NE				= 13,
	FILTER_OP_GT				= 14,
	FILTER_OP_LT				= 15,
	FILTER_OP_GE				= 16,
	FILTER_OP_LE				= 17,

	/* string binary comparator: apply to  */
	FILTER_OP_EQ_STRING			= 18,
	FILTER_OP_NE_STRING			= 19,
	FILTER_OP_GT_STRING			= 20,
	FILTER_OP_LT_STRING			= 21,
	FILTER_OP_GE_STRING			= 22,
	FILTER_OP_LE_STRING			= 23,

	/* s64 binary comparator */
	FILTER_OP_EQ_S64			= 24,
	FILTER_OP_NE_S64			= 25,
	FILTER_OP_GT_S64			= 26,
	FILTER_OP_LT_S64			= 27,
	FILTER_OP_GE_S64			= 28,
	FILTER_OP_LE_S64			= 29,

	/* double binary comparator */
	FILTER_OP_EQ_DOUBLE			= 30,
	FILTER_OP_NE_DOUBLE			= 31,
	FILTER_OP_GT_DOUBLE			= 32,
	FILTER_OP_LT_DOUBLE			= 33,
	FILTER_OP_GE_DOUBLE			= 34,
	FILTER_OP_LE_DOUBLE			= 35,

	/* Mixed S64-double binary comparators */
	FILTER_OP_EQ_DOUBLE_S64			= 36,
	FILTER_OP_NE_DOUBLE_S64			= 37,
	FILTER_OP_GT_DOUBLE_S64			= 38,
	FILTER_OP_LT_DOUBLE_S64			= 39,
	FILTER_OP_GE_DOUBLE_S64			= 40,
	FILTER_OP_LE_DOUBLE_S64			= 41,

	FILTER_OP_EQ_S64_DOUBLE			= 42,
	FILTER_OP_NE_S64_DOUBLE			= 43,
	FILTER_OP_GT_S64_DOUBLE			= 44,
	FILTER_OP_LT_S64_DOUBLE			= 45,
	FILTER_OP_GE_S64_DOUBLE			= 46,
	FILTER_OP_LE_S64_DOUBLE			= 47,

	/* unary */
	FILTER_OP_UNARY_PLUS			= 48,
	FILTER_OP_UNARY_MINUS			= 49,
	FILTER_OP_UNARY_NOT			= 50,
	FILTER_OP_UNARY_PLUS_S64		= 51,
	FILTER_OP_UNARY_MINUS_S64		= 52,
	FILTER_OP_UNARY_NOT_S64			= 53,
	FILTER_OP_UNARY_PLUS_DOUBLE		= 54,
	FILTER_OP_UNARY_MINUS_DOUBLE		= 55,
	FILTER_OP_UNARY_NOT_DOUBLE		= 56,

	/* logical */
	FILTER_OP_AND				= 57,
	FILTER_OP_OR				= 58,

	/* load field ref */
	FILTER_OP_LOAD_FIELD_REF		= 59,
	FILTER_OP_LOAD_FIELD_REF_STRING		= 60,
	FILTER_OP_LOAD_FIELD_REF_SEQUENCE	= 61,
	FILTER_OP_LOAD_FIELD_REF_S64		= 62,
	FILTER_OP_LOAD_FIELD_REF_DOUBLE		= 63,

	/* load immediate from operand */
	FILTER_OP_LOAD_STRING			= 64,
	FILTER_OP_LOAD_S64			= 65,
	FILTER_OP_LOAD_DOUBLE			= 66,

	/* cast */
	FILTER_OP_CAST_TO_S64			= 67,
	FILTER_OP_CAST_DOUBLE_TO_S64		= 68,
	FILTER_OP_CAST_NOP			= 69,

	/* get context ref */
	FILTER_OP_GET_CONTEXT_REF		= 70,
	FILTER_OP_GET_CONTEXT_REF_STRING	= 71,
	FILTER_OP_GET_CONTEXT_REF_S64		= 72,
	FILTER_OP_GET_CONTEXT_REF_DOUBLE	= 73,

	/* load userspace field ref */
	FILTER_OP_LOAD_FIELD_REF_USER_STRING	= 74,
	FILTER_OP_LOAD_FIELD_REF_USER_SEQUENCE	= 75,

	/*
	 * load immediate star globbing pattern (literal string)
	 * from immediate
	 */
	FILTER_OP_LOAD_STAR_GLOB_STRING		= 76,

	/* globbing pattern binary operator: apply to */
	FILTER_OP_EQ_STAR_GLOB_STRING		= 77,
	FILTER_OP_NE_STAR_GLOB_STRING		= 78,

	/*
	 * Instructions for recursive traversal through composed types.
	 */
	FILTER_OP_GET_CONTEXT_ROOT		= 79,
	FILTER_OP_GET_APP_CONTEXT_ROOT		= 80,
	FILTER_OP_GET_PAYLOAD_ROOT		= 81,

	FILTER_OP_GET_SYMBOL			= 82,
	FILTER_OP_GET_SYMBOL_FIELD		= 83,
	FILTER_OP_GET_INDEX_U16			= 84,
	FILTER_OP_GET_INDEX_U64			= 85,

	FILTER_OP_LOAD_FIELD			= 86,
	FILTER_OP_LOAD_FIELD_S8			= 87,
	FILTER_OP_LOAD_FIELD_S16		= 88,
	FILTER_OP_LOAD_FIELD_S32		= 89,
	FILTER_OP_LOAD_FIELD_S64		= 90,
	FILTER_OP_LOAD_FIELD_U8			= 91,
	FILTER_OP_LOAD_FIELD_U16		= 92,
	FILTER_OP_LOAD_FIELD_U32		= 93,
	FILTER_OP_LOAD_FIELD_U64		= 94,
	FILTER_OP_LOAD_FIELD_STRING		= 95,
	FILTER_OP_LOAD_FIELD_SEQUENCE		= 96,
	FILTER_OP_LOAD_FIELD_DOUBLE		= 97,

	FILTER_OP_UNARY_BIT_NOT			= 98,

	FILTER_OP_RETURN_S64			= 99,

	NR_FILTER_OPS,
};

typedef uint8_t filter_opcode_t;

struct load_op {
	filter_opcode_t op;
	char data[0];
	/* data to load. Size known by enum filter_opcode and null-term char. */
} LTTNG_PACKED;

struct binary_op {
	filter_opcode_t op;
} LTTNG_PACKED;

struct unary_op {
	filter_opcode_t op;
} LTTNG_PACKED;

/* skip_offset is absolute from start of bytecode */
struct logical_op {
	filter_opcode_t op;
	uint16_t skip_offset;	/* bytecode insn, if skip second test */
} LTTNG_PACKED;

struct cast_op {
	filter_opcode_t op;
} LTTNG_PACKED;

struct return_op {
	filter_opcode_t op;
} LTTNG_PACKED;

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
