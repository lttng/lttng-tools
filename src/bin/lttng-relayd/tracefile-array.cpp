/*
 * SPDX-FileCopyrightText: 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "tracefile-array.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>
#include <common/utils.hpp>

struct tracefile_array *tracefile_array_create(size_t count)
{
	struct tracefile_array *tfa = nullptr;
	int i;

	tfa = zmalloc<tracefile_array>();
	if (!tfa) {
		goto error;
	}
	tfa->tf = calloc<tracefile>(count);
	if (!tfa->tf) {
		goto error;
	}
	tfa->count = count;
	for (i = 0; i < count; i++) {
		tfa->tf[i].seq_head = -1ULL;
		tfa->tf[i].seq_tail = -1ULL;
	}
	tfa->seq_head = -1ULL;
	tfa->seq_tail = -1ULL;
	return tfa;

error:
	if (tfa) {
		free(tfa->tf);
	}
	free(tfa);
	return nullptr;
}

void tracefile_array_destroy(struct tracefile_array *tfa)
{
	if (!tfa) {
		return;
	}
	free(tfa->tf);
	free(tfa);
}

void tracefile_array_reset(struct tracefile_array *tfa)
{
	size_t count, i;

	count = tfa->count;
	for (i = 0; i < count; i++) {
		tfa->tf[i].seq_head = -1ULL;
		tfa->tf[i].seq_tail = -1ULL;
	}
	tfa->seq_head = -1ULL;
	tfa->seq_tail = -1ULL;
	tfa->file_head_read = 0;
	tfa->file_head_write = 0;
	tfa->file_tail = 0;
}

void tracefile_array_file_rotate(struct tracefile_array *tfa, enum tracefile_rotate_type type)
{
	uint64_t *headp, *tailp;

	if (!tfa->count) {
		/* Not in tracefile rotation mode. */
		return;
	}
	switch (type) {
	case TRACEFILE_ROTATE_READ:
		/*
		 * Rotate read head to write head position, thus allowing
		 * reader to consume the newly rotated head file.
		 */
		tfa->file_head_read = tfa->file_head_write;
		break;
	case TRACEFILE_ROTATE_WRITE:
		/* Rotate write head to next file, pushing tail if needed.  */
		tfa->file_head_write = (tfa->file_head_write + 1) % tfa->count;
		if (tfa->file_head_write == tfa->file_tail) {
			/* Move tail. */
			tfa->file_tail = (tfa->file_tail + 1) % tfa->count;
		}
		headp = &tfa->tf[tfa->file_head_write].seq_head;
		tailp = &tfa->tf[tfa->file_head_write].seq_tail;
		/*
		 * If we overwrite a file with content, we need to push the tail
		 * to the position following the content we are overwriting.
		 */
		if (*headp != -1ULL) {
			tfa->seq_tail = tfa->tf[tfa->file_tail].seq_tail;
		}
		/* Reset this file head/tail (overwrite). */
		*headp = -1ULL;
		*tailp = -1ULL;
		break;
	default:
		abort();
	}
}

void tracefile_array_commit_seq(struct tracefile_array *tfa, uint64_t new_seq_head)
{
	uint64_t *headp, *tailp;

	/* Increment overall head. */
	tfa->seq_head = new_seq_head;
	/* If we are committing our first index overall, set tail to head. */
	if (tfa->seq_tail == -1ULL) {
		tfa->seq_tail = new_seq_head;
	}
	if (!tfa->count) {
		/* Not in tracefile rotation mode. */
		return;
	}
	headp = &tfa->tf[tfa->file_head_write].seq_head;
	tailp = &tfa->tf[tfa->file_head_write].seq_tail;
	/* Update head tracefile seq_head. */
	*headp = tfa->seq_head;
	/*
	 * If we are committing our first index in this packet, set tail
	 * to this index seq count.
	 */
	if (*tailp == -1ULL) {
		*tailp = tfa->seq_head;
	}
}

uint64_t tracefile_array_get_read_file_index_head(struct tracefile_array *tfa)
{
	return tfa->file_head_read;
}

uint64_t tracefile_array_get_seq_head(struct tracefile_array *tfa)
{
	return tfa->seq_head;
}

uint64_t tracefile_array_get_file_index_tail(struct tracefile_array *tfa)
{
	return tfa->file_tail;
}

uint64_t tracefile_array_get_seq_tail(struct tracefile_array *tfa)
{
	return tfa->seq_tail;
}

bool tracefile_array_seq_in_file(struct tracefile_array *tfa, uint64_t file_index, uint64_t seq)
{
	if (!tfa->count) {
		/*
		 * Not in tracefile rotation mode; we are guaranteed to have the
		 * index in this file.
		 */
		return true;
	}
	LTTNG_ASSERT(file_index < tfa->count);
	if (seq == -1ULL) {
		return false;
	}
	return seq >= tfa->tf[file_index].seq_tail && seq <= tfa->tf[file_index].seq_head;
}
