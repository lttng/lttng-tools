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
#include <common/trace-chunk.h>

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
	/* previous data sequence number written to disk. */
	uint64_t prev_data_seq;
	/* previous index sequence number written to disk. */
	uint64_t prev_index_seq;
	/* seq num to encounter before closing. */
	uint64_t last_net_seq_num;

	/* FD on which to write the stream data. */
	struct stream_fd *stream_fd;
	/* index file on which to write the index data. */
	struct lttng_index_file *index_file;

	char *path_name;
	/*
	 * prev_path_name is only used for session rotation support.
	 * It is essentially used to work around the fact that index
	 * files are always created from the 'data' connection.
	 *
	 * Hence, it is possible to receive a ROTATE_STREAM command
	 * which affects the stream's path_name before the creation of
	 * an index file. In this situation, the index file of the
	 * 'previous' chunk would be created in the new destination folder.
	 *
	 * It would then be unlinked when the actual index of the new chunk
	 * is created.
	 */
	char *prev_path_name;
	char *channel_name;

	/* On-disk circular buffer of tracefiles. */
	uint64_t tracefile_size;
	uint64_t tracefile_size_current;
	uint64_t tracefile_count;

	/*
	 * Position in the tracefile where we have the full index also on disk.
	 */
	uint64_t pos_after_last_complete_data_index;

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
	/*
	 * When we have written the data and index corresponding to this
	 * seq_num, rotate the tracefile (session rotation). The path_name is
	 * already up-to-date.
	 * This is set to -1ULL when no rotation is pending.
	 *
	 * Always access with stream lock held.
	 */
	uint64_t rotate_at_seq_num;
	/*
	 * When rotate_at_seq_num != -1ULL, meaning that a rotation is ongoing,
	 * data_rotated and index_rotated respectively indicate if the stream's
	 * data and index have been rotated. A rotation is considered completed
	 * when both rotations have occurred.
	 */
	bool data_rotated;
	bool index_rotated;
	/*
	 * `trace_chunk` is the trace chunk to which the file currently
	 * being produced (if any) belongs.
	 */
	struct lttng_trace_chunk *trace_chunk;
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
