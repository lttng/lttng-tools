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

#define _GNU_SOURCE
#include <common/common.h>
#include <common/index/index.h>

#include "lttng-relayd.h"
#include "viewer-stream.h"

static void viewer_stream_destroy(struct relay_viewer_stream *vstream)
{
	free(vstream->path_name);
	free(vstream->channel_name);
	free(vstream);
}

static void viewer_stream_destroy_rcu(struct rcu_head *head)
{
	struct relay_viewer_stream *vstream =
		caa_container_of(head, struct relay_viewer_stream, rcu_node);

	viewer_stream_destroy(vstream);
}

struct relay_viewer_stream *viewer_stream_create(struct relay_stream *stream,
		enum lttng_viewer_seek seek_t)
{
	struct relay_viewer_stream *vstream;

	vstream = zmalloc(sizeof(*vstream));
	if (!vstream) {
		PERROR("relay viewer stream zmalloc");
		goto error;
	}

	vstream->path_name = strndup(stream->path_name, LTTNG_VIEWER_PATH_MAX);
	if (vstream->path_name == NULL) {
		PERROR("relay viewer path_name alloc");
		goto error;
	}
	vstream->channel_name = strndup(stream->channel_name,
			LTTNG_VIEWER_NAME_MAX);
	if (vstream->channel_name == NULL) {
		PERROR("relay viewer channel_name alloc");
		goto error;
	}

	switch (seek_t) {
	case LTTNG_VIEWER_SEEK_BEGINNING:
		vstream->current_tracefile_id = stream->oldest_tracefile_id;
		break;
	case LTTNG_VIEWER_SEEK_LAST:
		vstream->current_tracefile_id = stream->current_tracefile_id;
		break;
	default:
		goto error;
	}
	if (!stream_get(stream)) {
		ERR("Cannot get stream");
		goto error;
	}
	vstream->stream = stream;

	pthread_mutex_lock(&stream->lock);
	/*
	 * If we never received an index for the current stream, delay the opening
	 * of the index, otherwise open it right now.
	 */
	if (vstream->current_tracefile_id == stream->current_tracefile_id
			&& stream->total_index_received == 0) {
		vstream->index_fd = NULL;
	} else {
		int read_fd;

		read_fd = index_open(vstream->path_name, vstream->channel_name,
				stream->tracefile_count,
				vstream->current_tracefile_id);
		if (read_fd < 0) {
			goto error_unlock;
		}
		vstream->index_fd = stream_fd_create(read_fd);
		if (!vstream->index_fd) {
			if (close(read_fd)) {
				PERROR("close");
			}
			goto error_unlock;
		}
	}

	if (seek_t == LTTNG_VIEWER_SEEK_LAST && vstream->index_fd) {
		off_t lseek_ret;

		lseek_ret = lseek(vstream->index_fd->fd, 0, SEEK_END);
		if (lseek_ret < 0) {
			goto error_unlock;
		}
		vstream->last_sent_index = stream->total_index_received;
	}
	pthread_mutex_unlock(&stream->lock);

	if (stream->is_metadata) {
		rcu_assign_pointer(stream->trace->viewer_metadata_stream,
				vstream);
	}

	/* Globally visible after the add unique. */
	lttng_ht_node_init_u64(&vstream->stream_n, stream->stream_handle);
	lttng_ht_add_unique_u64(viewer_streams_ht, &vstream->stream_n);

	pthread_mutex_init(&vstream->reflock, NULL);
	urcu_ref_init(&vstream->ref);

	return vstream;

error_unlock:
	pthread_mutex_unlock(&stream->lock);
error:
	if (vstream) {
		viewer_stream_destroy(vstream);
	}
	return NULL;
}

static void viewer_stream_unpublish(struct relay_viewer_stream *vstream)
{
	int ret;
	struct lttng_ht_iter iter;

	iter.iter.node = &vstream->stream_n.node;
	ret = lttng_ht_del(viewer_streams_ht, &iter);
	assert(!ret);
}

static void viewer_stream_release(struct urcu_ref *ref)
{
	struct relay_viewer_stream *vstream = caa_container_of(ref,
			struct relay_viewer_stream, ref);

	if (vstream->stream->is_metadata) {
		rcu_assign_pointer(vstream->stream->trace->viewer_metadata_stream, NULL);
	}

	viewer_stream_unpublish(vstream);

	if (vstream->stream_fd) {
		stream_fd_put(vstream->stream_fd);
		vstream->stream_fd = NULL;
	}
	if (vstream->index_fd) {
		stream_fd_put(vstream->index_fd);
		vstream->index_fd = NULL;
	}
	if (vstream->stream) {
		stream_put(vstream->stream);
		vstream->stream = NULL;
	}
	call_rcu(&vstream->rcu_node, viewer_stream_destroy_rcu);
}

/* Must be called with RCU read-side lock held. */
bool viewer_stream_get(struct relay_viewer_stream *vstream)
{
	bool has_ref = false;

	pthread_mutex_lock(&vstream->reflock);
	if (vstream->ref.refcount != 0) {
		has_ref = true;
		urcu_ref_get(&vstream->ref);
	}
	pthread_mutex_unlock(&vstream->reflock);

	return has_ref;
}

/*
 * Get viewer stream by id.
 *
 * Return viewer stream if found else NULL.
 */
struct relay_viewer_stream *viewer_stream_get_by_id(uint64_t id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct relay_viewer_stream *vstream = NULL;

	rcu_read_lock();
	lttng_ht_lookup(viewer_streams_ht, &id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		DBG("Relay viewer stream %" PRIu64 " not found", id);
		goto end;
	}
	vstream = caa_container_of(node, struct relay_viewer_stream, stream_n);
	if (!viewer_stream_get(vstream)) {
		vstream = NULL;
	}
end:
	rcu_read_unlock();
	return vstream;
}

void viewer_stream_put(struct relay_viewer_stream *vstream)
{
	rcu_read_lock();
	pthread_mutex_lock(&vstream->reflock);
	urcu_ref_put(&vstream->ref, viewer_stream_release);
	pthread_mutex_unlock(&vstream->reflock);
	rcu_read_unlock();
}

/*
 * Returns whether the current tracefile is readable. If not, it has
 * been overwritten.
 * Must be called with rstream lock held.
 */
bool viewer_stream_is_tracefile_seq_readable(struct relay_viewer_stream *vstream,
		 uint64_t seq)
{
	struct relay_stream *stream = vstream->stream;

	if (seq >= stream->oldest_tracefile_seq
			&& seq <= stream->current_tracefile_seq) {
		/* seq is a readable file. */
		return true;
	} else {
		/* seq is not readable. */
		return false;
	}
}

/*
 * Rotate a stream to the next tracefile.
 *
 * Must be called with the rstream lock held.
 * Returns 0 on success, 1 on EOF, a negative value on error.
 */
int viewer_stream_rotate(struct relay_viewer_stream *vstream)
{
	int ret;
	struct relay_stream *stream = vstream->stream;

	/* Detect the last tracefile to open. */
	if (stream->total_index_received == vstream->last_sent_index
			&& stream->trace->session->connection_closed) {
		ret = 1;
		goto end;
	}

	if (stream->tracefile_count == 0) {
		/* Ignore rotation, there is none to do. */
		ret = 0;
		goto end;
	}

	if (!viewer_stream_is_tracefile_seq_readable(vstream,
			vstream->current_tracefile_seq + 1)) {
		vstream->current_tracefile_id =
				stream->oldest_tracefile_id;
		vstream->current_tracefile_seq =
				stream->oldest_tracefile_seq;
	} else {
		vstream->current_tracefile_id =
				(vstream->current_tracefile_id + 1)
					% stream->tracefile_count;
		vstream->current_tracefile_seq++;
	}

	if (vstream->index_fd) {
		stream_fd_put(vstream->index_fd);
		vstream->index_fd = NULL;
	}
	if (vstream->stream_fd) {
		stream_fd_put(vstream->stream_fd);
		vstream->stream_fd = NULL;
	}

	ret = index_open(vstream->path_name, vstream->channel_name,
			stream->tracefile_count,
			vstream->current_tracefile_id);
	if (ret < 0) {
		goto end;
	}
	vstream->index_fd = stream_fd_create(ret);
	if (vstream->index_fd) {
		ret = 0;
	} else {
		if (close(ret)) {
			PERROR("close");
		}
		ret = -1;
	}
end:
	return ret;
}

void print_viewer_streams(void)
{
	struct lttng_ht_iter iter;
	struct relay_viewer_stream *vstream;

	rcu_read_lock();
	cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter, vstream,
			stream_n.node) {
		if (!viewer_stream_get(vstream)) {
			continue;
		}
		DBG("vstream %p refcount %ld stream %" PRIu64 " trace %" PRIu64
			" session %" PRIu64,
			vstream,
			vstream->ref.refcount,
			vstream->stream->stream_handle,
			vstream->stream->trace->id,
			vstream->stream->trace->session->id);
		viewer_stream_put(vstream);
	}
	rcu_read_unlock();
}
