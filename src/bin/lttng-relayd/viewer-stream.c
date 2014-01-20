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
#include <common/index/index.h>

#include "lttng-relayd.h"
#include "viewer-stream.h"

static void free_stream(struct relay_viewer_stream *stream)
{
	assert(stream);

	free(stream->path_name);
	free(stream->channel_name);
	free(stream);
}

static void deferred_free_viewer_stream(struct rcu_head *head)
{
	struct relay_viewer_stream *stream =
		caa_container_of(head, struct relay_viewer_stream, rcu_node);

	free_stream(stream);
}

struct relay_viewer_stream *viewer_stream_create(struct relay_stream *stream,
		enum lttng_viewer_seek seek_t)
{
	struct relay_viewer_stream *vstream;

	assert(stream);

	vstream = zmalloc(sizeof(*vstream));
	if (!vstream) {
		PERROR("relay viewer stream zmalloc");
		goto error;
	}

	vstream->session_id = stream->session->id;
	vstream->stream_handle = stream->stream_handle;
	vstream->path_name = strndup(stream->path_name, LTTNG_VIEWER_PATH_MAX);
	vstream->channel_name = strndup(stream->channel_name,
			LTTNG_VIEWER_NAME_MAX);
	vstream->tracefile_count = stream->tracefile_count;
	vstream->metadata_flag = stream->metadata_flag;
	vstream->tracefile_count_last = -1ULL;

	switch (seek_t) {
	case VIEWER_SEEK_BEGINNING:
		vstream->tracefile_count_current = stream->oldest_tracefile_id;
		break;
	case VIEWER_SEEK_LAST:
		vstream->tracefile_count_current = stream->tracefile_count_current;
		break;
	default:
		assert(0);
		goto error;
	}

	vstream->ctf_trace = stream->ctf_trace;
	if (vstream->metadata_flag) {
		vstream->ctf_trace->viewer_metadata_stream = vstream;
	}
	uatomic_inc(&vstream->ctf_trace->refcount);

	/* Globally visible after the add unique. */
	lttng_ht_node_init_u64(&vstream->stream_n, stream->stream_handle);
	lttng_ht_add_unique_u64(viewer_streams_ht, &vstream->stream_n);

	vstream->index_read_fd = -1;
	vstream->read_fd = -1;

	/*
	 * This is to avoid a race between the initialization of this object and
	 * the close of the given stream. If the stream is unable to find this
	 * viewer stream when closing, this copy will at least take the latest
	 * value. We also need that for the seek_last.
	 */
	vstream->total_index_received = stream->total_index_received;

	/*
	 * If we never received an index for the current stream, delay the opening
	 * of the index, otherwise open it right now.
	 */
	if (vstream->tracefile_count_current == stream->tracefile_count_current
			&& vstream->total_index_received == 0) {
		vstream->index_read_fd = -1;
	} else {
		int read_fd;

		read_fd = index_open(vstream->path_name, vstream->channel_name,
				vstream->tracefile_count, vstream->tracefile_count_current);
		if (read_fd < 0) {
			goto error;
		}
		vstream->index_read_fd = read_fd;
	}

	if (seek_t == VIEWER_SEEK_LAST && vstream->index_read_fd >= 0) {
		off_t lseek_ret;

		lseek_ret = lseek(vstream->index_read_fd,
				vstream->total_index_received * sizeof(struct ctf_packet_index),
				SEEK_CUR);
		if (lseek_ret < 0) {
			goto error;
		}
		vstream->last_sent_index = vstream->total_index_received;
	}

	return vstream;

error:
	if (vstream) {
		free_stream(vstream);
	}
	return NULL;
}

void viewer_stream_delete(struct relay_viewer_stream *stream)
{
	int ret;
	struct lttng_ht_iter iter;

	iter.iter.node = &stream->stream_n.node;
	ret = lttng_ht_del(viewer_streams_ht, &iter);
	assert(!ret);
}

void viewer_stream_destroy(struct relay_viewer_stream *stream)
{
	int ret;
	unsigned long ret_ref;

	assert(stream);
	ret_ref = uatomic_add_return(&stream->ctf_trace->refcount, -1);
	assert(ret_ref >= 0);

	if (stream->read_fd >= 0) {
		ret = close(stream->read_fd);
		if (ret < 0) {
			PERROR("close read_fd");
		}
	}
	if (stream->index_read_fd >= 0) {
		ret = close(stream->index_read_fd);
		if (ret < 0) {
			PERROR("close index_read_fd");
		}
	}

	/*
	 * If the only stream left in the HT is the metadata stream,
	 * we need to remove it because we won't detect a EOF for this
	 * stream.
	 */
	if (ret_ref == 1 && stream->ctf_trace->viewer_metadata_stream) {
		viewer_stream_delete(stream->ctf_trace->viewer_metadata_stream);
		viewer_stream_destroy(stream->ctf_trace->viewer_metadata_stream);
		stream->ctf_trace->metadata_stream = NULL;
		DBG("Freeing ctf_trace %" PRIu64, stream->ctf_trace->id);
		/*
		 * The streaming-side is already closed and we can't receive a new
		 * stream concurrently at this point (since the session is being
		 * destroyed), so when we detect the refcount equals 0, we are the
		 * only owners of the ctf_trace and we can free it ourself.
		 */
		free(stream->ctf_trace);
	}

	call_rcu(&stream->rcu_node, deferred_free_viewer_stream);
}

/*
 * Find viewer stream by id. RCU read side lock MUST be acquired.
 *
 * Return stream if found else NULL.
 */
struct relay_viewer_stream *viewer_stream_find_by_id(uint64_t id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct relay_viewer_stream *stream = NULL;

	lttng_ht_lookup(viewer_streams_ht, &id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		DBG("Relay viewer stream %" PRIu64 " not found", id);
		goto end;
	}
	stream = caa_container_of(node, struct relay_viewer_stream, stream_n);

end:
	return stream;
}

/*
 * Rotate a stream to the next tracefile.
 *
 * Returns 0 on success, 1 on EOF, a negative value on error.
 */
int viewer_stream_rotate(struct relay_viewer_stream *vstream,
		struct relay_stream *stream)
{
	int ret;
	uint64_t tracefile_id;

	assert(vstream);

	tracefile_id = (vstream->tracefile_count_current + 1) %
		vstream->tracefile_count;

	/* Detect the last tracefile to open. */
	if (vstream->tracefile_count_last != -1ULL &&
			vstream->tracefile_count_last ==
			vstream->tracefile_count_current) {
		ret = 1;
		goto end;
	}

	/*
	 * If the stream on the streaming side still exists, lock to execute
	 * rotation in order to avoid races between a modification on the index
	 * values.
	 */
	if (stream) {
		pthread_mutex_lock(&stream->viewer_stream_rotation_lock);
	}

	/*
	 * The writer and the reader are not working in the same tracefile, we can
	 * read up to EOF, we don't care about the total_index_received.
	 */
	if (!stream || (stream->tracefile_count_current != tracefile_id)) {
		vstream->close_write_flag = 1;
	} else {
		/*
		 * We are opening a file that is still open in write, make sure we
		 * limit our reading to the number of indexes received.
		 */
		vstream->close_write_flag = 0;
		if (stream) {
			vstream->total_index_received = stream->total_index_received;
		}
	}
	vstream->tracefile_count_current = tracefile_id;

	ret = close(vstream->index_read_fd);
	if (ret < 0) {
		PERROR("close index file %d", vstream->index_read_fd);
	}
	vstream->index_read_fd = -1;

	ret = close(vstream->read_fd);
	if (ret < 0) {
		PERROR("close tracefile %d", vstream->read_fd);
	}
	vstream->read_fd = -1;

	pthread_mutex_lock(&vstream->overwrite_lock);
	vstream->abort_flag = 0;
	pthread_mutex_unlock(&vstream->overwrite_lock);

	if (stream) {
		pthread_mutex_unlock(&stream->viewer_stream_rotation_lock);
	}

	ret = index_open(vstream->path_name, vstream->channel_name,
			vstream->tracefile_count, vstream->tracefile_count_current);
	if (ret < 0) {
		goto error;
	}
	vstream->index_read_fd = ret;

	ret = 0;

end:
error:
	return ret;
}
