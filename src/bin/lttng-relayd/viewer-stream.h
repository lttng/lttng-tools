#ifndef _VIEWER_STREAM_H
#define _VIEWER_STREAM_H

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

#include <common/hashtable/hashtable.h>

#include "ctf-trace.h"
#include "lttng-viewer-abi.h"
#include "stream.h"

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

	/* FD from which to read the stream data. */
	struct stream_fd *stream_fd;
	/* index file from which to read the index data. */
	struct lttng_index_file *index_file;

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
		enum lttng_viewer_seek seek_t);

struct relay_viewer_stream *viewer_stream_get_by_id(uint64_t id);
bool viewer_stream_get(struct relay_viewer_stream *vstream);
void viewer_stream_put(struct relay_viewer_stream *vstream);
int viewer_stream_rotate(struct relay_viewer_stream *vstream);
bool viewer_stream_is_tracefile_seq_readable(struct relay_viewer_stream *vstream,
		uint64_t seq);
void print_viewer_streams(void);

#endif /* _VIEWER_STREAM_H */
