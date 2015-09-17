#ifndef _STREAM_H
#define _STREAM_H

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

#include <limits.h>
#include <inttypes.h>
#include <pthread.h>
#include <urcu/list.h>

#include <common/hashtable/hashtable.h>

#include "session.h"
#include "stream-fd.h"
#include "tracefile-array.h"

/*
 * Represents a stream in the relay
 */
struct relay_stream {
	uint64_t stream_handle;

	struct urcu_ref ref;
	/* Back reference to trace. Protected by refcount on trace object. */
	struct ctf_trace *trace;

	/*
	 * To protect from concurrent read/update. The viewer stream
	 * lock nests inside the stream lock. The stream lock nests
	 * inside the ctf_trace lock.
	 */
	pthread_mutex_t lock;
	uint64_t prev_seq;		/* previous data sequence number encountered. */
	uint64_t last_net_seq_num;	/* seq num to encounter before closing. */

	/* FD on which to write the stream data. */
	struct stream_fd *stream_fd;
	/* index file on which to write the index data. */
	struct lttng_index_file *index_file;

	char *path_name;
	char *channel_name;

	/* On-disk circular buffer of tracefiles. */
	uint64_t tracefile_size;
	uint64_t tracefile_size_current;
	uint64_t tracefile_count;

	/*
	 * Counts the number of received indexes. The "tag" associated
	 * with an index is taken before incrementing this seqcount.
	 * Therefore, the sequence tag associated with the last index
	 * received is always index_received_seqcount - 1.
	 */
	uint64_t index_received_seqcount;

	/*
	 * Tracefile array is an index of the stream trace files,
	 * indexed by position. It allows keeping track of the oldest
	 * available indexes when overwriting trace files in tracefile
	 * rotation.
	 */
	struct tracefile_array *tfa;

	bool closed;		/* Stream is closed. */
	bool close_requested;	/* Close command has been received. */

	/*
	 * Counts number of indexes in indexes_ht. Redundant info.
	 * Protected by stream lock.
	 */
	int indexes_in_flight;
	struct lttng_ht *indexes_ht;

	/*
	 * If the stream is inactive, this field is updated with the
	 * live beacon timestamp end, when it is active, this
	 * field == -1ULL.
	 */
	uint64_t beacon_ts_end;

	/* CTF stream ID, -1ULL when unset (first packet not received yet). */
	uint64_t ctf_stream_id;

	/* Indicate if the stream was initialized for a data pending command. */
	bool data_pending_check_done;

	/* Is this stream a metadata stream ? */
	int32_t is_metadata;
	/* Amount of metadata received (bytes). */
	uint64_t metadata_received;

	/*
	 * Member of the stream list in struct ctf_trace.
	 * Updates are protected by the stream_list_lock.
	 * Traversals are protected by RCU.
	 */
	struct cds_list_head stream_node;
	/*
	 * Temporary list belonging to the connection until all streams
	 * are received for that connection.
	 * Member of the stream recv list in the connection.
	 * Updates are protected by the stream_recv_list_lock.
	 * Traversals are protected by RCU.
	 */
	bool in_recv_list;
	struct cds_list_head recv_node;
	bool published;	/* Protected by session lock. */
	/*
	 * Node of stream within global stream hash table.
	 */
	struct lttng_ht_node_u64 node;
	bool in_stream_ht;		/* is stream in stream hash table. */
	struct rcu_head rcu_node;	/* For call_rcu teardown. */
};

struct relay_stream *stream_create(struct ctf_trace *trace,
	uint64_t stream_handle, char *path_name,
	char *channel_name, uint64_t tracefile_size,
	uint64_t tracefile_count);

struct relay_stream *stream_get_by_id(uint64_t stream_id);
bool stream_get(struct relay_stream *stream);
void stream_put(struct relay_stream *stream);
void try_stream_close(struct relay_stream *stream);
void stream_publish(struct relay_stream *stream);
void print_relay_streams(void);

#endif /* _STREAM_H */
