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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <assert.h>

#include <common/common.h>
#include <common/utils.h>

#include "lttng-relayd.h"
#include "index.h"

/*
 * Deferred free of a relay index object. MUST only be called by a call RCU.
 */
static void deferred_free_relay_index(struct rcu_head *head)
{
	struct relay_index *index =
		caa_container_of(head, struct relay_index, rcu_node);

	if (index->to_close_fd >= 0) {
		int ret;

		ret = close(index->to_close_fd);
		if (ret < 0) {
			PERROR("Relay index to close fd %d", index->to_close_fd);
		}
	}

	relay_index_free(index);
}

/*
 * Allocate a new relay index object using the given stream ID and sequence
 * number as the hash table key.
 *
 * Return allocated object or else NULL on error.
 */
struct relay_index *relay_index_create(uint64_t stream_id,
		uint64_t net_seq_num)
{
	struct relay_index *index;

	DBG2("Creating relay index with stream id %" PRIu64 " and seqnum %" PRIu64,
			stream_id, net_seq_num);

	index = zmalloc(sizeof(*index));
	if (index == NULL) {
		PERROR("Relay index zmalloc");
		goto error;
	}

	index->to_close_fd = -1;
	lttng_ht_node_init_two_u64(&index->index_n, stream_id, net_seq_num);

error:
	return index;
}

/*
 * Find a relayd index in the given hash table.
 *
 * Return index object or else NULL on error.
 */
struct relay_index *relay_index_find(uint64_t stream_id, uint64_t net_seq_num)
{
	struct lttng_ht_node_two_u64 *node;
	struct lttng_ht_iter iter;
	struct lttng_ht_two_u64 key;
	struct relay_index *index = NULL;

	DBG3("Finding index for stream id %" PRIu64 " and seq_num %" PRIu64,
			stream_id, net_seq_num);

	key.key1 = stream_id;
	key.key2 = net_seq_num;

	lttng_ht_lookup(indexes_ht, (void *)(&key), &iter);
	node = lttng_ht_iter_get_node_two_u64(&iter);
	if (node == NULL) {
		goto end;
	}
	index = caa_container_of(node, struct relay_index, index_n);

end:
	DBG2("Index %sfound in HT for stream ID %" PRIu64 " and seqnum %" PRIu64,
			(index == NULL) ? "NOT " : "", stream_id, net_seq_num);
	return index;
}

/*
 * Add unique relay index to the given hash table. In case of a collision, the
 * already existing object is put in the given _index variable.
 *
 * RCU read side lock MUST be acquired.
 */
void relay_index_add(struct relay_index *index, struct relay_index **_index)
{
	struct cds_lfht_node *node_ptr;

	assert(index);

	DBG2("Adding relay index with stream id %" PRIu64 " and seqnum %" PRIu64,
			index->key.key1, index->key.key2);

	node_ptr = cds_lfht_add_unique(indexes_ht->ht,
			indexes_ht->hash_fct((void *) &index->index_n.key, lttng_ht_seed),
			indexes_ht->match_fct, (void *) &index->index_n.key,
			&index->index_n.node);
	if (node_ptr != &index->index_n.node) {
		*_index = caa_container_of(node_ptr, struct relay_index, index_n.node);
	}
}

/*
 * Write index on disk to the given fd. Once done error or not, it is removed
 * from the hash table and destroy the object.
 *
 * MUST be called with a RCU read side lock held.
 *
 * Return 0 on success else a negative value.
 */
int relay_index_write(int fd, struct relay_index *index)
{
	int ret;
	struct lttng_ht_iter iter;

	DBG2("Writing index for stream ID %" PRIu64 " and seq num %" PRIu64
			" on fd %d", index->key.key1, index->key.key2, fd);

	/* Delete index from hash table. */
	iter.iter.node = &index->index_n.node;
	ret = lttng_ht_del(indexes_ht, &iter);
	assert(!ret);
	call_rcu(&index->rcu_node, deferred_free_relay_index);

	return index_write(fd, &index->index_data, sizeof(index->index_data));
}

/*
 * Free the given index.
 */
void relay_index_free(struct relay_index *index)
{
	free(index);
}

/*
 * Safely free the given index using a call RCU.
 */
void relay_index_free_safe(struct relay_index *index)
{
	if (!index) {
		return;
	}

	call_rcu(&index->rcu_node, deferred_free_relay_index);
}

/*
 * Delete index from the given hash table.
 *
 * RCU read side lock MUST be acquired.
 */
void relay_index_delete(struct relay_index *index)
{
	int ret;
	struct lttng_ht_iter iter;

	DBG3("Relay index with stream ID %" PRIu64 " and seq num %" PRIu64
			"deleted.", index->key.key1, index->key.key2);

	/* Delete index from hash table. */
	iter.iter.node = &index->index_n.node;
	ret = lttng_ht_del(indexes_ht, &iter);
	assert(!ret);
}

/*
 * Destroy every relay index with the given stream id as part of the key.
 */
void relay_index_destroy_by_stream_id(uint64_t stream_id)
{
	struct lttng_ht_iter iter;
	struct relay_index *index;

	rcu_read_lock();
	cds_lfht_for_each_entry(indexes_ht->ht, &iter.iter, index, index_n.node) {
		if (index->key.key1 == stream_id) {
			relay_index_delete(index);
			relay_index_free_safe(index);
		}
	}
	rcu_read_unlock();
}
