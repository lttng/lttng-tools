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

/*
 * Represents a stream in the relay
 */
struct relay_stream {
	uint64_t stream_handle;

	/*
	 * reflock used to synchronize the closing of this stream.
	 * stream reflock nests inside viewer stream reflock.
	 * stream reflock nests inside index reflock.
	 */
	pthread_mutex_t reflock;
	struct urcu_ref ref;
	/* Back reference to trace. Protected by refcount on trace object. */
	struct ctf_trace *trace;

	/*
	 * To protect from concurrent read/update. The viewer stream
	 * lock nests inside the stream lock. The stream lock nests
	 * inside the ctf_trace lock.
	 */
	pthread_mutex_t lock;
	uint64_t prev_seq;		/* previous data sequence number encountered */
	uint64_t last_net_seq_num;	/* seq num to encounter before closing. */

	/* FD on which to write the stream data. */
	struct stream_fd *stream_fd;
	/* FD on which to write the index data. */
	struct stream_fd *index_fd;

	char *path_name;
	char *channel_name;

	/* on-disk circular buffer of tracefiles */
	uint64_t tracefile_size;
	uint64_t tracefile_size_current;
	uint64_t tracefile_count;
	uint64_t current_tracefile_id;

	uint64_t current_tracefile_seq;	/* Free-running counter */
	uint64_t oldest_tracefile_seq;	/* Free-running counter */

	/* To inform the viewer up to where it can go back in time. */
	uint64_t oldest_tracefile_id;

	struct lttng_ht *indexes_ht;
	/*
	 * Counts number of indexes in indexes_ht. Redundant info.
	 * Protected by stream lock.
	 */
	uint64_t total_index_received;

	bool closed;	/* Stream is closed. */

	int indexes_in_flight;
	/*
	 * If the stream is inactive, this field is updated with the
	 * live beacon timestamp end, when it is active, this
	 * field == -1ULL.
	 */
	uint64_t beacon_ts_end;
	/*
	 * CTF stream ID, -1ULL when unset.
	 */
	uint64_t ctf_stream_id;

	/* Indicate if the stream was initialized for a data pending command. */
	bool data_pending_check_done;

	/* Is this stream a metadata stream ? */
	int32_t is_metadata;
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
	struct rcu_head rcu_node;	/* For call_rcu teardown. */
};

struct relay_stream *stream_create(struct ctf_trace *trace,
	uint64_t stream_handle, char *path_name,
	char *channel_name, uint64_t tracefile_size,
	uint64_t tracefile_count);

struct relay_stream *stream_get_by_id(uint64_t stream_id);
bool stream_get(struct relay_stream *stream);
void stream_put(struct relay_stream *stream);
void stream_close(struct relay_stream *stream);
void stream_publish(struct relay_stream *stream);
void print_relay_streams(void);

#endif /* _STREAM_H */
