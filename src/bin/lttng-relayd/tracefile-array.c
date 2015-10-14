/*
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <common/common.h>
#include <common/utils.h>
#include <common/defaults.h>

#include "tracefile-array.h"

struct tracefile_array *tracefile_array_create(size_t count)
{
	struct tracefile_array *tfa = NULL;
	int i;

	tfa = zmalloc(sizeof(*tfa));
	if (!tfa) {
		goto error;
	}
	tfa->tf = zmalloc(sizeof(*tfa->tf) * count);
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
	return NULL;
}

void tracefile_array_destroy(struct tracefile_array *tfa)
{
	if (!tfa) {
		return;
	}
	free(tfa->tf);
	free(tfa);
}

void tracefile_array_file_rotate(struct tracefile_array *tfa)
{
	uint64_t *headp, *tailp;

	if (!tfa->count) {
		/* Not in tracefile rotation mode. */
		return;
	}
	/* Rotate to next file.  */
	tfa->file_head = (tfa->file_head + 1) % tfa->count;
	if (tfa->file_head == tfa->file_tail) {
		/* Move tail. */
		tfa->file_tail = (tfa->file_tail + 1) % tfa->count;
	}
	headp = &tfa->tf[tfa->file_head].seq_head;
	tailp = &tfa->tf[tfa->file_head].seq_tail;
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
}

void tracefile_array_commit_seq(struct tracefile_array *tfa)
{
	uint64_t *headp, *tailp;

	/* Increment overall head. */
	tfa->seq_head++;
	/* If we are committing our first index overall, set tail to 0. */
	if (tfa->seq_tail == -1ULL) {
		tfa->seq_tail = 0;
	}
	if (!tfa->count) {
		/* Not in tracefile rotation mode. */
		return;
	}
	headp = &tfa->tf[tfa->file_head].seq_head;
	tailp = &tfa->tf[tfa->file_head].seq_tail;
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

uint64_t tracefile_array_get_file_index_head(struct tracefile_array *tfa)
{
	return tfa->file_head;
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

bool tracefile_array_seq_in_file(struct tracefile_array *tfa,
		uint64_t file_index, uint64_t seq)
{
	if (!tfa->count) {
		/*
		 * Not in tracefile rotation mode; we are guaranteed to have the
		 * index in this file.
		 */
		return true;
	}
	assert(file_index < tfa->count);
	if (seq == -1ULL) {
		return false;
	}
	if (seq >= tfa->tf[file_index].seq_tail
			&& seq <= tfa->tf[file_index].seq_head) {
		return true;
	} else {
		return false;
	}
}
