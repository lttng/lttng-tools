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

/* Stub */
struct relay_stream;

/*
 * Shadow copy of the relay_stream structure for the viewer side.
 */
struct relay_viewer_stream {
	struct urcu_ref ref;
	pthread_mutex_t reflock;

	/* Back ref to stream */
	struct relay_stream *stream;

	/* FD from which to read the stream data. */
	struct stream_fd *stream_fd;
	/* FD from which to read the index data. */
	struct stream_fd *index_fd;

	char *path_name;
	char *channel_name;

	uint64_t current_tracefile_id;
	uint64_t current_tracefile_seq;	/* Free-running counter */

	uint64_t last_sent_index;

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
