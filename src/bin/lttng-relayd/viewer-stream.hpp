#ifndef _VIEWER_STREAM_H
#define _VIEWER_STREAM_H

/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ctf-trace.hpp"
#include "lttng-viewer-abi.hpp"
#include "stream.hpp"

#include <common/hashtable/hashtable.hpp>

#include <inttypes.h>
#include <limits.h>
#include <pthread.h>

struct relay_stream;

/*
 * The viewer stream's lifetime is the intersection of their viewer connection's
 * lifetime and the duration during which at least:
 * a) their input source is still active
 * b) they still have data left to send to the client.
 *
 * This means that both the sessiond/consumerd connection or the viewer
 * connection may tear down (and unpublish) a relay_viewer_stream.
 *
 * Viewer stream updates are protected by their associated stream's lock.
 */
struct relay_viewer_stream {
	struct urcu_ref ref;

	/* Back ref to stream. */
	struct relay_stream *stream;

	struct {
		struct fs_handle *handle;
		struct lttng_trace_chunk *trace_chunk;
	} stream_file;
	/* index file from which to read the index data. */
	struct lttng_index_file *index_file;
	/*
	 * Last seen rotation count in stream.
	 *
	 * Sampled on every change to the viewer stream trace chunk,
	 * this allows the live server to determine if it saw the latest
	 * rotation that occurred on the receiving end.
	 */
	uint64_t last_seen_rotation_count;

	char *path_name;
	char *channel_name;

	uint64_t current_tracefile_id;

	/*
	 * Counts the number of sent indexes. The "tag" associated
	 * with an index to send is the current index_received_seqcount,
	 * because we increment index_received_seqcount after sending
	 * each index. This index_received_seqcount counter can also be
	 * updated when catching up with the producer.
	 */
	uint64_t index_sent_seqcount;

	/* Indicates if this stream has been sent to a viewer client. */
	bool sent_flag;
	/* For metadata stream, how much metadata has been sent. */
	uint64_t metadata_sent;

	struct lttng_ht_node_u64 stream_n;
	struct rcu_head rcu_node;
};

struct relay_viewer_stream *viewer_stream_create(struct relay_stream *stream,
						 struct lttng_trace_chunk *viewer_trace_chunk,
						 enum lttng_viewer_seek seek_t);

struct relay_viewer_stream *viewer_stream_get_by_id(uint64_t id);
bool viewer_stream_get(struct relay_viewer_stream *vstream);
void viewer_stream_put(struct relay_viewer_stream *vstream);
int viewer_stream_rotate(struct relay_viewer_stream *vstream);
bool viewer_stream_is_tracefile_seq_readable(struct relay_viewer_stream *vstream, uint64_t seq);
void print_viewer_streams(void);
void viewer_stream_close_files(struct relay_viewer_stream *vstream);
void viewer_stream_sync_tracefile_array_tail(struct relay_viewer_stream *vstream);

#endif /* _VIEWER_STREAM_H */
