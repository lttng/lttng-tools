#ifndef _RELAY_INDEX_H
#define _RELAY_INDEX_H

/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <inttypes.h>
#include <pthread.h>

#include <common/hashtable/hashtable.h>
#include <common/index/index.h>

#include "stream-fd.h"

struct relay_stream;

struct relay_index {
	/*
	 * index lock nests inside stream lock.
	 */
	struct urcu_ref ref;		/* Reference from getters. */
	struct relay_stream *stream;	/* Back ref to stream */

	pthread_mutex_t lock;
	/*
	 * index file on which to write the index data. May differ from
	 * stream->index_file due to tracefile rotation.
	 */
	struct lttng_index_file *index_file;

	/* Index packet data. This is the data that is written on disk. */
	struct ctf_packet_index index_data;

	bool has_index_data;
	bool flushed;
	bool in_hash_table;

	/*
	 * Node within indexes_ht that corresponds to this struct
	 * relay_index. Indexed by net_seq_num, which is unique for this
	 * index across the stream.
	 */
	struct lttng_ht_node_u64 index_n;
	struct rcu_head rcu_node;	/* For call_rcu teardown. */
};

struct relay_index *relay_index_get_by_id_or_create(struct relay_stream *stream,
		uint64_t net_seq_num);
void relay_index_put(struct relay_index *index);
int relay_index_set_file(struct relay_index *index,
		struct lttng_index_file *index_file,
		uint64_t data_offset);
int relay_index_set_data(struct relay_index *index,
                const struct ctf_packet_index *data);
int relay_index_try_flush(struct relay_index *index);

void relay_index_close_all(struct relay_stream *stream);
void relay_index_close_partial_fd(struct relay_stream *stream);
uint64_t relay_index_find_last(struct relay_stream *stream);

#endif /* _RELAY_INDEX_H */
