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
#include <common/common.h>

#include "index.h"
#include "stream.h"
#include "viewer-stream.h"

static void rcu_destroy_stream(struct rcu_head *head)
{
	struct relay_stream *stream =
		caa_container_of(head, struct relay_stream, rcu_node);

	free(stream->path_name);
	free(stream->channel_name);
	free(stream);
}

/*
 * Get stream from stream id from the given hash table. Return stream if found
 * else NULL.
 *
 * Need to be called with RCU read-side lock held.
 */
struct relay_stream *stream_find_by_id(struct lttng_ht *ht,
		uint64_t stream_id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct relay_stream *stream = NULL;

	assert(ht);

	lttng_ht_lookup(ht, &stream_id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node == NULL) {
		DBG("Relay stream %" PRIu64 " not found", stream_id);
		goto end;
	}
	stream = caa_container_of(node, struct relay_stream, node);

end:
	return stream;
}

/*
 * Close a given stream. If an assosiated viewer stream exists it is updated.
 *
 * RCU read side lock MUST be acquired.
 *
 * Return 0 if close was successful or 1 if already closed.
 */
int stream_close(struct relay_session *session, struct relay_stream *stream)
{
	int delret, ret;
	struct relay_viewer_stream *vstream;
	struct ctf_trace *ctf_trace;

	assert(stream);

	pthread_mutex_lock(&stream->lock);

	if (stream->terminated_flag) {
		/* This stream is already closed. Ignore. */
		ret = 1;
		goto end_unlock;
	}

	DBG("Closing stream id %" PRIu64, stream->stream_handle);

	if (stream->fd >= 0) {
		delret = close(stream->fd);
		if (delret < 0) {
			PERROR("close stream");
		}
	}

	if (stream->index_fd >= 0) {
		delret = close(stream->index_fd);
		if (delret < 0) {
			PERROR("close stream index_fd");
		}
	}

	vstream = viewer_stream_find_by_id(stream->stream_handle);
	if (vstream) {
		/*
		 * Set the last good value into the viewer stream. This is done
		 * right before the stream gets deleted from the hash table. The
		 * lookup failure on the live thread side of a stream indicates
		 * that the viewer stream index received value should be used.
		 */
		pthread_mutex_lock(&stream->viewer_stream_rotation_lock);
		vstream->total_index_received = stream->total_index_received;
		vstream->tracefile_count_last = stream->tracefile_count_current;
		vstream->close_write_flag = 1;
		pthread_mutex_unlock(&stream->viewer_stream_rotation_lock);
	}

	/* Cleanup index of that stream. */
	relay_index_destroy_by_stream_id(stream->stream_handle);

	ctf_trace = ctf_trace_find_by_path(session->ctf_traces_ht,
			stream->path_name);
	assert(ctf_trace);
	ctf_trace_put_ref(ctf_trace);

	stream->close_flag = 1;
	stream->terminated_flag = 1;
	ret = 0;

end_unlock:
	pthread_mutex_unlock(&stream->lock);
	return ret;
}

void stream_delete(struct lttng_ht *ht, struct relay_stream *stream)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(ht);
	assert(stream);

	iter.iter.node = &stream->node.node;
	ret = lttng_ht_del(ht, &iter);
	assert(!ret);

	cds_list_del(&stream->trace_list);
}

void stream_destroy(struct relay_stream *stream)
{
	assert(stream);

	call_rcu(&stream->rcu_node, rcu_destroy_stream);
}
