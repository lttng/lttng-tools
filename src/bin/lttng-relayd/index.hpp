#ifndef _RELAY_INDEX_H
#define _RELAY_INDEX_H

/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/hashtable/hashtable.hpp>
#include <common/index/index.hpp>

#include <inttypes.h>
#include <pthread.h>

struct relay_stream;
struct relay_connection;
struct lttcomm_relayd_index;

struct relay_index {
	/*
	 * index lock nests inside stream lock.
	 */
	struct urcu_ref ref; /* Reference from getters. */
	struct relay_stream *stream; /* Back ref to stream */

	pthread_mutex_t lock;
	/*
	 * index file on which to write the index data. May differ from
	 * stream->index_file due to tracefile rotation.
	 */
	struct lttng_index_file *index_file;

	/* Index packet data. This is the data that is written on disk. */
	struct ctf_packet_index index_data;
	/* Data + padding size of this packet, filled by the data thread. */
	uint64_t total_size;

	bool has_index_data;
	bool flushed;
	bool in_hash_table;

	/*
	 * Node within indexes_ht that corresponds to this struct
	 * relay_index. Indexed by net_seq_num, which is unique for this
	 * index across the stream.
	 */
	struct lttng_ht_node_u64 index_n;
	struct rcu_head rcu_node; /* For call_rcu teardown. */
};

struct relay_index *relay_index_get_by_id_or_create(struct relay_stream *stream,
						    uint64_t net_seq_num);
void relay_index_put(struct relay_index *index);
int relay_index_set_file(struct relay_index *index,
			 struct lttng_index_file *index_file,
			 uint64_t data_offset);
int relay_index_set_data(struct relay_index *index, const struct ctf_packet_index *data);
int relay_index_try_flush(struct relay_index *index);

void relay_index_close_all(struct relay_stream *stream);
void relay_index_close_partial_fd(struct relay_stream *stream);
uint64_t relay_index_find_last(struct relay_stream *stream);
int relay_index_switch_all_files(struct relay_stream *stream);
int relay_index_set_control_data(struct relay_index *index,
				 const struct lttcomm_relayd_index *data,
				 unsigned int minor_version);

#endif /* _RELAY_INDEX_H */
