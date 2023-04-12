#ifndef _TRACEFILE_ARRAY_H
#define _TRACEFILE_ARRAY_H

/*
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>

struct tracefile {
	/* Per-tracefile head/tail seq. */
	uint64_t seq_head; /* Newest seqcount. Inclusive. */
	uint64_t seq_tail; /* Oldest seqcount. Inclusive. */
};

enum tracefile_rotate_type {
	TRACEFILE_ROTATE_READ,
	TRACEFILE_ROTATE_WRITE,
};

/*
 * Represents an array of trace files in a stream.
 * head is the most recent file/trace packet.
 * tail is the oldest file/trace packet.
 *
 * There are two heads: a "read" head and a "write" head. The "write" head is
 * the position of the newest data file. The "read" head position is only moved
 * forward when the index is received.
 *
 * The viewer uses the "read" head position as upper bound, which
 * ensures it never attempts to open a non-existing index file.
 */
struct tracefile_array {
	struct tracefile *tf;
	size_t count;

	/* Current head/tail files. */
	uint64_t file_head_read;
	uint64_t file_head_write;
	uint64_t file_tail;

	/* Overall head/tail seq for the entire array. Inclusive. */
	uint64_t seq_head;
	uint64_t seq_tail;
};

struct tracefile_array *tracefile_array_create(size_t count);
void tracefile_array_destroy(struct tracefile_array *tfa);

void tracefile_array_file_rotate(struct tracefile_array *tfa, enum tracefile_rotate_type type);
void tracefile_array_commit_seq(struct tracefile_array *tfa, uint64_t new_seq_head);
void tracefile_array_reset(struct tracefile_array *tfa);

uint64_t tracefile_array_get_read_file_index_head(struct tracefile_array *tfa);
/* May return -1ULL in the case where we have not received any indexes yet. */
uint64_t tracefile_array_get_seq_head(struct tracefile_array *tfa);

uint64_t tracefile_array_get_file_index_tail(struct tracefile_array *tfa);
/* May return -1ULL in the case where we have not received any indexes yet. */
uint64_t tracefile_array_get_seq_tail(struct tracefile_array *tfa);

bool tracefile_array_seq_in_file(struct tracefile_array *tfa, uint64_t file_index, uint64_t seq);

#endif /* _STREAM_H */
