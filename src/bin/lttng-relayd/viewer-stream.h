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

#ifndef _VIEWER_STREAM_H
#define _VIEWER_STREAM_H

#include <limits.h>
#include <inttypes.h>
#include <pthread.h>

#include <common/hashtable/hashtable.h>

#include "ctf-trace.h"
#include "lttng-viewer-abi.h"
#include "stream.h"

/* Stub */
struct relay_stream;

/*
 * Shadow copy of the relay_stream structure for the viewer side.  The only
 * fields updated by the writer (streaming side) after allocation are :
 * total_index_received and close_flag. Everything else is updated by the
 * reader (viewer side).
 */
struct relay_viewer_stream {
	uint64_t stream_handle;
	uint64_t session_id;
	int read_fd;
	int index_read_fd;
	char *path_name;
	char *channel_name;
	uint64_t last_sent_index;
	uint64_t total_index_received;
	uint64_t tracefile_count;
	uint64_t tracefile_count_current;
	/* Stop after reading this tracefile. */
	uint64_t tracefile_count_last;
	struct lttng_ht_node_u64 stream_n;
	struct rcu_head rcu_node;
	struct ctf_trace *ctf_trace;
	/*
	 * This lock blocks only when the writer is about to start overwriting
	 * a file currently read by the reader.
	 *
	 * This is nested INSIDE the viewer_stream_rotation_lock.
	 */
	pthread_mutex_t overwrite_lock;
	/* Information telling us if the stream is a metadata stream. */
	unsigned int metadata_flag:1;
	/*
	 * Information telling us that the stream is closed in write, so
	 * we don't expect new indexes and we can read up to EOF.
	 */
	unsigned int close_write_flag:1;
	/*
	 * If the streaming side closes a FD in use in the viewer side,
	 * it sets this flag to inform that it is a normal error.
	 */
	unsigned int abort_flag:1;
	/* Indicates if this stream has been sent to a viewer client. */
	unsigned int sent_flag:1;
};

struct relay_viewer_stream *viewer_stream_create(struct relay_stream *stream,
		enum lttng_viewer_seek seek_t, struct ctf_trace *ctf_trace);
struct relay_viewer_stream *viewer_stream_find_by_id(uint64_t id);
void viewer_stream_destroy(struct ctf_trace *ctf_trace,
		struct relay_viewer_stream *stream);
void viewer_stream_delete(struct relay_viewer_stream *stream);
int viewer_stream_rotate(struct relay_viewer_stream *vstream,
		struct relay_stream *stream);

#endif /* _VIEWER_STREAM_H */
