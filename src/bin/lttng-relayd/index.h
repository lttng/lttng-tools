/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
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

#ifndef _RELAY_INDEX_H
#define _RELAY_INDEX_H

#include <inttypes.h>
#include <pthread.h>

#include <common/hashtable/hashtable.h>
#include <common/index/index.h>

struct relay_index {
	/* FD on which to write the index data. */
	int fd;
	/*
	 * When destroying this object, this fd is checked and if valid, close it
	 * so this is basically a lazy close of the previous fd corresponding to
	 * the same stream id. This is used for the rotate file feature.
	 */
	int to_close_fd;

	/* Index packet data. This is the data that is written on disk. */
	struct lttng_packet_index index_data;

	/* key1 = stream_id, key2 = net_seq_num */
	struct lttng_ht_two_u64 key;
	struct lttng_ht_node_two_u64 index_n;
	struct rcu_head rcu_node;
	pthread_mutex_t mutex;
};

struct relay_index *relay_index_create(uint64_t stream_id,
		uint64_t net_seq_num);
struct relay_index *relay_index_find(uint64_t stream_id, uint64_t net_seq_num);
void relay_index_add(struct relay_index *index, struct relay_index **_index);
int relay_index_write(int fd, struct relay_index *index);
void relay_index_free(struct relay_index *index);
void relay_index_free_safe(struct relay_index *index);
void relay_index_delete(struct relay_index *index);
void relay_index_destroy_by_stream_id(uint64_t stream_id);

#endif /* _RELAY_INDEX_H */
