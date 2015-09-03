#ifndef _TRACEFILE_ARRAY_H
#define _TRACEFILE_ARRAY_H

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

#include <limits.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>

struct tracefile {
	/* Per-tracefile head/tail seq. */
	uint64_t seq_head;	/* Newest seqcount. Inclusive. */
	uint64_t seq_tail;	/* Oldest seqcount. Inclusive. */
};

/*
 * Represents an array of trace files in a stream.
 */
struct tracefile_array {
	struct tracefile *tf;
	size_t count;

	/* Current head/tail files. */
	uint64_t file_head;
	uint64_t file_tail;

	/* Overall head/tail seq for the entire array. Inclusive. */
	uint64_t seq_head;
	uint64_t seq_tail;
};

struct tracefile_array *tracefile_array_create(size_t count);
void tracefile_array_destroy(struct tracefile_array *tfa);

void tracefile_array_file_rotate(struct tracefile_array *tfa);
void tracefile_array_commit_seq(struct tracefile_array *tfa);

uint64_t tracefile_array_get_file_index_head(struct tracefile_array *tfa);
/* May return -1ULL in the case where we have not received any indexes yet. */
uint64_t tracefile_array_get_seq_head(struct tracefile_array *tfa);

uint64_t tracefile_array_get_file_index_tail(struct tracefile_array *tfa);
/* May return -1ULL in the case where we have not received any indexes yet. */
uint64_t tracefile_array_get_seq_tail(struct tracefile_array *tfa);

bool tracefile_array_seq_in_file(struct tracefile_array *tfa,
		uint64_t file_index, uint64_t seq);

#endif /* _STREAM_H */
