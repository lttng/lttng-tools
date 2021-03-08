/*
 * Copyright 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_BYTECODE_H
#define LTTNG_COMMON_BYTECODE_H

#include <stdint.h>

#include "common/macros.h"
#include "common/sessiond-comm/sessiond-comm.h"

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

enum bytecode_op {
	BYTECODE_OP_UNKNOWN				= 0,

	BYTECODE_OP_RETURN				= 1,

	/* binary */
	BYTECODE_OP_MUL					= 2,
	BYTECODE_OP_DIV					= 3,
	BYTECODE_OP_MOD					= 4,
	BYTECODE_OP_PLUS				= 5,
	BYTECODE_OP_MINUS				= 6,
	BYTECODE_OP_BIT_RSHIFT				= 7,
	BYTECODE_OP_BIT_LSHIFT				= 8,
	BYTECODE_OP_BIT_AND				= 9,
	BYTECODE_OP_BIT_OR				= 10,
	BYTECODE_OP_BIT_XOR				= 11,

	/* binary comparators */
	BYTECODE_OP_EQ					= 12,
	BYTECODE_OP_NE					= 13,
	BYTECODE_OP_GT					= 14,
	BYTECODE_OP_LT					= 15,
	BYTECODE_OP_GE					= 16,
	BYTECODE_OP_LE					= 17,

	/* string binary comparator: apply to  */
	BYTECODE_OP_EQ_STRING				= 18,
	BYTECODE_OP_NE_STRING				= 19,
	BYTECODE_OP_GT_STRING				= 20,
	BYTECODE_OP_LT_STRING				= 21,
	BYTECODE_OP_GE_STRING				= 22,
	BYTECODE_OP_LE_STRING				= 23,

	/* s64 binary comparator */
	BYTECODE_OP_EQ_S64				= 24,
	BYTECODE_OP_NE_S64				= 25,
	BYTECODE_OP_GT_S64				= 26,
	BYTECODE_OP_LT_S64				= 27,
	BYTECODE_OP_GE_S64				= 28,
	BYTECODE_OP_LE_S64				= 29,

	/* double binary comparator */
	BYTECODE_OP_EQ_DOUBLE				= 30,
	BYTECODE_OP_NE_DOUBLE				= 31,
	BYTECODE_OP_GT_DOUBLE				= 32,
	BYTECODE_OP_LT_DOUBLE				= 33,
	BYTECODE_OP_GE_DOUBLE				= 34,
	BYTECODE_OP_LE_DOUBLE				= 35,

	/* Mixed S64-double binary comparators */
	BYTECODE_OP_EQ_DOUBLE_S64			= 36,
	BYTECODE_OP_NE_DOUBLE_S64			= 37,
	BYTECODE_OP_GT_DOUBLE_S64			= 38,
	BYTECODE_OP_LT_DOUBLE_S64			= 39,
	BYTECODE_OP_GE_DOUBLE_S64			= 40,
	BYTECODE_OP_LE_DOUBLE_S64			= 41,

	BYTECODE_OP_EQ_S64_DOUBLE			= 42,
	BYTECODE_OP_NE_S64_DOUBLE			= 43,
	BYTECODE_OP_GT_S64_DOUBLE			= 44,
	BYTECODE_OP_LT_S64_DOUBLE			= 45,
	BYTECODE_OP_GE_S64_DOUBLE			= 46,
	BYTECODE_OP_LE_S64_DOUBLE			= 47,

	/* unary */
	BYTECODE_OP_UNARY_PLUS				= 48,
	BYTECODE_OP_UNARY_MINUS				= 49,
	BYTECODE_OP_UNARY_NOT				= 50,
	BYTECODE_OP_UNARY_PLUS_S64			= 51,
	BYTECODE_OP_UNARY_MINUS_S64			= 52,
	BYTECODE_OP_UNARY_NOT_S64			= 53,
	BYTECODE_OP_UNARY_PLUS_DOUBLE			= 54,
	BYTECODE_OP_UNARY_MINUS_DOUBLE			= 55,
	BYTECODE_OP_UNARY_NOT_DOUBLE			= 56,

	/* logical */
	BYTECODE_OP_AND					= 57,
	BYTECODE_OP_OR					= 58,

	/* load field ref */
	BYTECODE_OP_LOAD_FIELD_REF			= 59,
	BYTECODE_OP_LOAD_FIELD_REF_STRING		= 60,
	BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE		= 61,
	BYTECODE_OP_LOAD_FIELD_REF_S64			= 62,
	BYTECODE_OP_LOAD_FIELD_REF_DOUBLE		= 63,

	/* load immediate from operand */
	BYTECODE_OP_LOAD_STRING				= 64,
	BYTECODE_OP_LOAD_S64				= 65,
	BYTECODE_OP_LOAD_DOUBLE				= 66,

	/* cast */
	BYTECODE_OP_CAST_TO_S64				= 67,
	BYTECODE_OP_CAST_DOUBLE_TO_S64			= 68,
	BYTECODE_OP_CAST_NOP				= 69,

	/* get context ref */
	BYTECODE_OP_GET_CONTEXT_REF			= 70,
	BYTECODE_OP_GET_CONTEXT_REF_STRING		= 71,
	BYTECODE_OP_GET_CONTEXT_REF_S64			= 72,
	BYTECODE_OP_GET_CONTEXT_REF_DOUBLE		= 73,

	/* load userspace field ref */
	BYTECODE_OP_LOAD_FIELD_REF_USER_STRING		= 74,
	BYTECODE_OP_LOAD_FIELD_REF_USER_SEQUENCE	= 75,

	/*
	 * load immediate star globbing pattern (literal string)
	 * from immediate
	 */
	BYTECODE_OP_LOAD_STAR_GLOB_STRING		= 76,

	/* globbing pattern binary operator: apply to */
	BYTECODE_OP_EQ_STAR_GLOB_STRING			= 77,
	BYTECODE_OP_NE_STAR_GLOB_STRING			= 78,

	/*
	 * Instructions for recursive traversal through composed types.
	 */
	BYTECODE_OP_GET_CONTEXT_ROOT			= 79,
	BYTECODE_OP_GET_APP_CONTEXT_ROOT		= 80,
	BYTECODE_OP_GET_PAYLOAD_ROOT			= 81,

	BYTECODE_OP_GET_SYMBOL				= 82,
	BYTECODE_OP_GET_SYMBOL_FIELD			= 83,
	BYTECODE_OP_GET_INDEX_U16			= 84,
	BYTECODE_OP_GET_INDEX_U64			= 85,

	BYTECODE_OP_LOAD_FIELD				= 86,
	BYTECODE_OP_LOAD_FIELD_S8			= 87,
	BYTECODE_OP_LOAD_FIELD_S16			= 88,
	BYTECODE_OP_LOAD_FIELD_S32			= 89,
	BYTECODE_OP_LOAD_FIELD_S64			= 90,
	BYTECODE_OP_LOAD_FIELD_U8			= 91,
	BYTECODE_OP_LOAD_FIELD_U16			= 92,
	BYTECODE_OP_LOAD_FIELD_U32			= 93,
	BYTECODE_OP_LOAD_FIELD_U64			= 94,
	BYTECODE_OP_LOAD_FIELD_STRING			= 95,
	BYTECODE_OP_LOAD_FIELD_SEQUENCE			= 96,
	BYTECODE_OP_LOAD_FIELD_DOUBLE			= 97,

	BYTECODE_OP_UNARY_BIT_NOT			= 98,

	BYTECODE_OP_RETURN_S64				= 99,

	NR_BYTECODE_OPS,
};

typedef uint8_t bytecode_opcode_t;

struct load_op {
	bytecode_opcode_t op;

	/*
	 * data to load. Size known by enum bytecode_opcode_t and null-term
	 * char.
	 */
	char data[0];
} LTTNG_PACKED;

struct binary_op {
	bytecode_opcode_t op;
} LTTNG_PACKED;

struct unary_op {
	bytecode_opcode_t op;
} LTTNG_PACKED;

/* skip_offset is absolute from start of bytecode */
struct logical_op {
	bytecode_opcode_t op;
	uint16_t skip_offset;	/* bytecode insn, if skip second test */
} LTTNG_PACKED;

struct cast_op {
	bytecode_opcode_t op;
} LTTNG_PACKED;

struct return_op {
	bytecode_opcode_t op;
} LTTNG_PACKED;

struct lttng_bytecode_alloc {
	uint32_t alloc_len;
	struct lttng_bytecode b;
};

LTTNG_HIDDEN int bytecode_init(struct lttng_bytecode_alloc **fb);
LTTNG_HIDDEN int bytecode_push(struct lttng_bytecode_alloc **fb,
		const void *data, uint32_t align, uint32_t len);
LTTNG_HIDDEN int bytecode_push_logical(struct lttng_bytecode_alloc **fb,
		struct logical_op *data, uint32_t align, uint32_t len,
		uint16_t *skip_offset);
LTTNG_HIDDEN struct lttng_bytecode *lttng_bytecode_copy(
		const struct lttng_bytecode *orig_f);

LTTNG_HIDDEN int bytecode_push_get_payload_root(
		struct lttng_bytecode_alloc **bytecode);
LTTNG_HIDDEN int bytecode_push_get_context_root(
		struct lttng_bytecode_alloc **bytecode);
LTTNG_HIDDEN int bytecode_push_get_app_context_root(
		struct lttng_bytecode_alloc **bytecode);
LTTNG_HIDDEN int bytecode_push_get_index_u64(
		struct lttng_bytecode_alloc **bytecode, uint64_t index);
LTTNG_HIDDEN int bytecode_push_get_symbol(
		struct lttng_bytecode_alloc **bytecode,
		struct lttng_bytecode_alloc **bytecode_reloc,
		const char *symbol);

static inline
unsigned int bytecode_get_len(struct lttng_bytecode *bytecode)
{
	return bytecode->len;
}

#endif /* LTTNG_COMMON_BYTECODE_H */
