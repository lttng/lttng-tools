/*
 * Copyright 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "bytecode.h"

#include <errno.h>

#include "common/align.h"

#define INIT_ALLOC_SIZE 4

static inline int get_count_order(unsigned int count)
{
	int order;

	order = lttng_fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

LTTNG_HIDDEN
int bytecode_init(struct lttng_bytecode_alloc **fb)
{
	uint32_t alloc_len;

	alloc_len = sizeof(struct lttng_bytecode_alloc) + INIT_ALLOC_SIZE;
	*fb = calloc(alloc_len, 1);
	if (!*fb) {
		return -ENOMEM;
	} else {
		(*fb)->alloc_len = alloc_len;
		return 0;
	}
}

static
int32_t bytecode_reserve(struct lttng_bytecode_alloc **fb, uint32_t align, uint32_t len)
{
	int32_t ret;
	uint32_t padding = offset_align((*fb)->b.len, align);
	uint32_t new_len = (*fb)->b.len + padding + len;
	uint32_t new_alloc_len = sizeof(struct lttng_bytecode_alloc) + new_len;
	uint32_t old_alloc_len = (*fb)->alloc_len;

	if (new_len > LTTNG_FILTER_MAX_LEN)
		return -EINVAL;

	if (new_alloc_len > old_alloc_len) {
		struct lttng_bytecode_alloc *newptr;

		new_alloc_len =
			max_t(uint32_t, 1U << get_count_order(new_alloc_len), old_alloc_len << 1);
		newptr = realloc(*fb, new_alloc_len);
		if (!newptr)
			return -ENOMEM;
		*fb = newptr;
		/* We zero directly the memory from start of allocation. */
		memset(&((char *) *fb)[old_alloc_len], 0, new_alloc_len - old_alloc_len);
		(*fb)->alloc_len = new_alloc_len;
	}
	(*fb)->b.len += padding;
	ret = (*fb)->b.len;
	(*fb)->b.len += len;
	return ret;
}

LTTNG_HIDDEN
int bytecode_push(struct lttng_bytecode_alloc **fb, const void *data,
		uint32_t align, uint32_t len)
{
	int32_t offset;

	offset = bytecode_reserve(fb, align, len);
	if (offset < 0)
		return offset;
	memcpy(&(*fb)->b.data[offset], data, len);
	return 0;
}

LTTNG_HIDDEN
int bytecode_push_logical(struct lttng_bytecode_alloc **fb,
		struct logical_op *data,
		uint32_t align, uint32_t len,
		uint16_t *skip_offset)
{
	int32_t offset;

	offset = bytecode_reserve(fb, align, len);
	if (offset < 0)
		return offset;
	memcpy(&(*fb)->b.data[offset], data, len);
	*skip_offset =
		(void *) &((struct logical_op *) &(*fb)->b.data[offset])->skip_offset
			- (void *) &(*fb)->b.data[0];
	return 0;
}

LTTNG_HIDDEN
int bytecode_push_get_payload_root(struct lttng_bytecode_alloc **bytecode)
{
	int ret;
	struct load_op *insn;
	const uint32_t insn_len = sizeof(struct load_op);

	insn = calloc(insn_len, 1);
	if (!insn) {
		ret = -ENOMEM;
		goto end;
	}

	insn->op = BYTECODE_OP_GET_PAYLOAD_ROOT;
	ret = bytecode_push(bytecode, insn, 1, insn_len);
	free(insn);
end:
	return ret;
}

LTTNG_HIDDEN
int bytecode_push_get_context_root(struct lttng_bytecode_alloc **bytecode)
{
	int ret;
	struct load_op *insn;
	const uint32_t insn_len = sizeof(struct load_op);

	insn = calloc(insn_len, 1);
	if (!insn) {
		ret = -ENOMEM;
		goto end;
	}

	insn->op = BYTECODE_OP_GET_CONTEXT_ROOT;
	ret = bytecode_push(bytecode, insn, 1, insn_len);
	free(insn);
end:
	return ret;
}

LTTNG_HIDDEN
int bytecode_push_get_app_context_root(struct lttng_bytecode_alloc **bytecode)
{
	int ret;
	struct load_op *insn;
	const uint32_t insn_len = sizeof(struct load_op);

	insn = calloc(insn_len, 1);
	if (!insn) {
		ret = -ENOMEM;
		goto end;
	}

	insn->op = BYTECODE_OP_GET_APP_CONTEXT_ROOT;
	ret = bytecode_push(bytecode, insn, 1, insn_len);
	free(insn);
end:
	return ret;
}

LTTNG_HIDDEN
int bytecode_push_get_index_u64(struct lttng_bytecode_alloc **bytecode,
		uint64_t index)
{
	int ret;
	struct load_op *insn;
	struct get_index_u64 index_op_data;
	const uint32_t insn_len =
			sizeof(struct load_op) + sizeof(struct get_index_u64);

	insn = calloc(insn_len, 1);
	if (!insn) {
		ret = -ENOMEM;
		goto end;
	}

	insn->op = BYTECODE_OP_GET_INDEX_U64;
	index_op_data.index = index;
	memcpy(insn->data, &index_op_data, sizeof(index));
	ret = bytecode_push(bytecode, insn, 1, insn_len);

	free(insn);
end:
	return ret;
}

LTTNG_HIDDEN
int bytecode_push_get_symbol(struct lttng_bytecode_alloc **bytecode,
		struct lttng_bytecode_alloc **bytecode_reloc,
		const char *symbol)
{
	int ret;
	struct load_op *insn;
	struct get_symbol symbol_offset;
	uint32_t reloc_offset_u32;
	uint16_t reloc_offset;
	uint32_t bytecode_reloc_offset_u32;
	const uint32_t insn_len =
			sizeof(struct load_op) + sizeof(struct get_symbol);

	insn = calloc(insn_len, 1);
	if (!insn) {
		ret = -ENOMEM;
		goto end;
	}

	insn->op = BYTECODE_OP_GET_SYMBOL;

	/*
	 * Get offset in the reloc portion at which the symbol name
	 * will end up at (GET_SYMBOL's operand points there).
	 */
	bytecode_reloc_offset_u32 = bytecode_get_len(&(*bytecode_reloc)->b) +
			sizeof(reloc_offset);
	symbol_offset.offset = (uint16_t) bytecode_reloc_offset_u32;
	memcpy(insn->data, &symbol_offset, sizeof(symbol_offset));

	/*
	 * Get offset in the bytecode where the opcode will end up at,
	 * the reloc offset points to it.
	 */
	reloc_offset_u32 = bytecode_get_len(&(*bytecode)->b);
	if (reloc_offset_u32 > LTTNG_FILTER_MAX_LEN - 1) {
		ret = -EINVAL;
		goto end;
	}
	reloc_offset = (uint16_t) reloc_offset_u32;

	/* Append op in bytecode. */
	ret = bytecode_push(bytecode, insn, 1, insn_len);
	if (ret) {
		goto end;
	}

	/* Append reloc offset. */
	ret = bytecode_push(bytecode_reloc, &reloc_offset,
			1, sizeof(reloc_offset));
	if (ret) {
		goto end;
	}

	/* Append symbol name. */
	ret = bytecode_push(bytecode_reloc, symbol, 1, strlen(symbol) + 1);

end:
	free(insn);
	return ret;
}

/*
 * Allocate an lttng_bytecode object and copy the given original bytecode.
 *
 * Return allocated bytecode or NULL on error.
 */
LTTNG_HIDDEN
struct lttng_bytecode *lttng_bytecode_copy(
		const struct lttng_bytecode *orig_f)
{
	struct lttng_bytecode *bytecode = NULL;

	bytecode = zmalloc(sizeof(*bytecode) + orig_f->len);
	if (!bytecode) {
		goto error;
	}

	memcpy(bytecode, orig_f, sizeof(*bytecode) + orig_f->len);

error:
	return bytecode;
}
