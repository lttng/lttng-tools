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
#include <common/optional.h>
#include <common/buffer-view.h>

#include "session.h"
#include "stream-fd.h"
#include "tracefile-array.h"

struct lttcomm_relayd_index;

struct relay_stream_rotation {
	/*
	 * Indicates if the stream's data and index have been rotated. A
	 * rotation is considered completed when both rotations have occurred.
	 */
	bool data_rotated;
	bool index_rotated;
	/*
	 * Sequence number of the first packet of the new trace chunk to which
	 * the stream is rotating.
	 */
	uint64_t seq_num;
	struct lttng_trace_chunk *next_trace_chunk;
};

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
	char *channel_name;

	/* On-disk circular buffer of tracefiles. */
	uint64_t tracefile_size;
	uint64_t tracefile_size_current;
	/* Max number of trace files for this stream. */
	uint64_t tracefile_count;
	/*
	 * Index of the currently active file for this stream's on-disk
	 * ring buffer.
	 */
	uint64_t tracefile_current_index;
	/*
	 * Indicates that the on-disk buffer has wrapped around. Stream
	 * files shall be unlinked before being opened after this has occurred.
	 */
	bool tracefile_wrapped_around;

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
	bool is_metadata;
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
	/* Protected by session lock. */
	bool published;
	/*
	 * Node of stream within global stream hash table.
	 */
	struct lttng_ht_node_u64 node;
	bool in_stream_ht;		/* is stream in stream hash table. */
	struct rcu_head rcu_node;	/* For call_rcu teardown. */
	/*
	 * The trace chunk to which the file currently being produced (if any)
	 * belongs.
	 */
	struct lttng_trace_chunk *trace_chunk;
	LTTNG_OPTIONAL(struct relay_stream_rotation) ongoing_rotation;
};

struct relay_stream *stream_create(struct ctf_trace *trace,
	uint64_t stream_handle, char *path_name,
	char *channel_name, uint64_t tracefile_size,
	uint64_t tracefile_count);

struct relay_stream *stream_get_by_id(uint64_t stream_id);
bool stream_get(struct relay_stream *stream);
void stream_put(struct relay_stream *stream);
int stream_rotate_output_files(struct relay_session *session,
		struct relay_stream *stream);
int stream_set_pending_rotation(struct relay_stream *stream,
		struct lttng_trace_chunk *next_trace_chunk,
		uint64_t rotation_sequence_number);
void try_stream_close(struct relay_stream *stream);
void stream_publish(struct relay_stream *stream);
int stream_init_packet(struct relay_stream *stream, size_t packet_size,
		bool *file_rotated);
int stream_write(struct relay_stream *stream,
		const struct lttng_buffer_view *packet, size_t padding_len);
/* Called after the reception of a complete data packet. */
int stream_update_index(struct relay_stream *stream, uint64_t net_seq_num,
		bool rotate_index, bool *flushed, uint64_t total_size);
int stream_complete_packet(struct relay_stream *stream,
		size_t packet_total_size, uint64_t sequence_number,
		bool index_flushed);
/* Index info is in host endianness. */
int stream_add_index(struct relay_stream *stream,
		const struct lttcomm_relayd_index *index_info);
int stream_reset_file(struct relay_stream *stream);

void print_relay_streams(void);

#endif /* _STREAM_H */
