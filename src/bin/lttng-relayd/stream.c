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
#define _LGPL_SOURCE
#include <common/common.h>
#include <common/utils.h>
#include <common/defaults.h>
#include <urcu/rculist.h>
#include <sys/stat.h>

#include "lttng-relayd.h"
#include "index.h"
#include "stream.h"
#include "viewer-stream.h"

/* Should be called with RCU read-side lock held. */
bool stream_get(struct relay_stream *stream)
{
	bool has_ref = false;

	pthread_mutex_lock(&stream->reflock);
	if (stream->ref.refcount != 0) {
		has_ref = true;
		urcu_ref_get(&stream->ref);
	}
	pthread_mutex_unlock(&stream->reflock);

	return has_ref;
}

/*
 * Get stream from stream id from the streams hash table. Return stream
 * if found else NULL. A stream reference is taken when a stream is
 * returned. stream_put() must be called on that stream.
 */
struct relay_stream *stream_get_by_id(uint64_t stream_id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct relay_stream *stream = NULL;

	rcu_read_lock();
	lttng_ht_lookup(relay_streams_ht, &stream_id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		DBG("Relay stream %" PRIu64 " not found", stream_id);
		goto end;
	}
	stream = caa_container_of(node, struct relay_stream, node);
	if (!stream_get(stream)) {
		stream = NULL;
	}
end:
	rcu_read_unlock();
	return stream;
}

/*
 * We keep ownership of path_name and channel_name.
 */
struct relay_stream *stream_create(struct ctf_trace *trace,
	uint64_t stream_handle, char *path_name,
	char *channel_name, uint64_t tracefile_size,
	uint64_t tracefile_count)
{
	int ret;
	struct relay_stream *stream = NULL;
	struct relay_session *session = trace->session;

	stream = zmalloc(sizeof(struct relay_stream));
	if (stream == NULL) {
		PERROR("relay stream zmalloc");
		ret = -1;
		goto error_no_alloc;
	}

	stream->stream_handle = stream_handle;
	stream->prev_seq = -1ULL;
	stream->ctf_stream_id = -1ULL;
	stream->tracefile_size = tracefile_size;
	stream->tracefile_count = tracefile_count;
	stream->path_name = path_name;
	stream->channel_name = channel_name;
	lttng_ht_node_init_u64(&stream->node, stream->stream_handle);
	pthread_mutex_init(&stream->lock, NULL);
	pthread_mutex_init(&stream->reflock, NULL);
	urcu_ref_init(&stream->ref);
	ctf_trace_get(trace);
	stream->trace = trace;

	stream->indexes_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!stream->indexes_ht) {
		ERR("Cannot created indexes_ht");
		ret = -1;
		goto end;
	}

	ret = utils_mkdir_recursive(stream->path_name, S_IRWXU | S_IRWXG);
	if (ret < 0) {
		ERR("relay creating output directory");
		goto end;
	}

	/*
	 * No need to use run_as API here because whatever we receives,
	 * the relayd uses its own credentials for the stream files.
	 */
	ret = utils_create_stream_file(stream->path_name, stream->channel_name,
			stream->tracefile_size, 0, relayd_uid, relayd_gid, NULL);
	if (ret < 0) {
		ERR("Create output file");
		goto end;
	}
	stream->stream_fd = stream_fd_create(ret);
	if (!stream->stream_fd) {
		if (close(ret)) {
			PERROR("Error closing file %d", ret);
		}
		ret = -1;
		goto end;
	}
	if (stream->tracefile_size) {
		DBG("Tracefile %s/%s_0 created", stream->path_name, stream->channel_name);
	} else {
		DBG("Tracefile %s/%s created", stream->path_name, stream->channel_name);
	}

	if (!strncmp(stream->channel_name, DEFAULT_METADATA_NAME, NAME_MAX)) {
		stream->is_metadata = 1;
	}

	stream->in_recv_list = true;

	/*
	 * Add the stream in the recv list of the session. Once the end stream
	 * message is received, all session streams are published.
	 */
	pthread_mutex_lock(&session->recv_list_lock);
	cds_list_add_rcu(&stream->recv_node, &session->recv_list);
	session->stream_count++;
	pthread_mutex_unlock(&session->recv_list_lock);

	/*
	 * Both in the ctf_trace object and the global stream ht since the data
	 * side of the relayd does not have the concept of session.
	 */
	lttng_ht_add_unique_u64(relay_streams_ht, &stream->node);

	DBG("Relay new stream added %s with ID %" PRIu64, stream->channel_name,
			stream->stream_handle);
	ret = 0;

end:
	if (ret) {
		if (stream->stream_fd) {
			stream_fd_put(stream->stream_fd);
			stream->stream_fd = NULL;
		}
		stream_put(stream);
		stream = NULL;
	}
	return stream;

error_no_alloc:
	/*
	 * path_name and channel_name need to be freed explicitly here
	 * because we cannot rely on stream_put().
	 */
	free(path_name);
	free(channel_name);
	return NULL;
}

/*
 * Called with the session lock held.
 */
void stream_publish(struct relay_stream *stream)
{
	struct relay_session *session;

	pthread_mutex_lock(&stream->lock);
	if (stream->published) {
		goto unlock;
	}

	session = stream->trace->session;

	pthread_mutex_lock(&session->recv_list_lock);
	if (stream->in_recv_list) {
		cds_list_del_rcu(&stream->recv_node);
		stream->in_recv_list = false;
	}
	pthread_mutex_unlock(&session->recv_list_lock);

	pthread_mutex_lock(&stream->trace->stream_list_lock);
	cds_list_add_rcu(&stream->stream_node, &stream->trace->stream_list);
	pthread_mutex_unlock(&stream->trace->stream_list_lock);

	stream->published = true;
unlock:
	pthread_mutex_unlock(&stream->lock);
}

/*
 * Only called from destroy. No stream lock needed, since there is a
 * single user at this point. This is ensured by having the refcount
 * reaching 0.
 */
static void stream_unpublish(struct relay_stream *stream)
{
	if (!stream->published) {
		return;
	}
	pthread_mutex_lock(&stream->trace->stream_list_lock);
	cds_list_del_rcu(&stream->stream_node);
	pthread_mutex_unlock(&stream->trace->stream_list_lock);

	stream->published = false;
}

static void stream_destroy(struct relay_stream *stream)
{
	if (stream->indexes_ht) {
		lttng_ht_destroy(stream->indexes_ht);
	}
	free(stream->path_name);
	free(stream->channel_name);
	free(stream);
}

static void stream_destroy_rcu(struct rcu_head *rcu_head)
{
	struct relay_stream *stream =
		caa_container_of(rcu_head, struct relay_stream, rcu_node);

	stream_destroy(stream);
}

static void stream_release(struct urcu_ref *ref)
{
	struct relay_stream *stream =
		caa_container_of(ref, struct relay_stream, ref);
	struct relay_session *session;
	int ret;
	struct lttng_ht_iter iter;

	session = stream->trace->session;

	DBG("Releasing stream id %" PRIu64, stream->stream_handle);

	pthread_mutex_lock(&session->recv_list_lock);
	session->stream_count--;
	if (stream->in_recv_list) {
		cds_list_del_rcu(&stream->recv_node);
		stream->in_recv_list = false;
	}
	pthread_mutex_unlock(&session->recv_list_lock);

	iter.iter.node = &stream->node.node;
	ret = lttng_ht_del(relay_streams_ht, &iter);
	assert(!ret);

	stream_unpublish(stream);

	if (stream->stream_fd) {
		stream_fd_put(stream->stream_fd);
		stream->stream_fd = NULL;
	}
	if (stream->index_fd) {
		stream_fd_put(stream->index_fd);
		stream->index_fd = NULL;
	}
	if (stream->trace) {
		ctf_trace_put(stream->trace);
		stream->trace = NULL;
	}

	call_rcu(&stream->rcu_node, stream_destroy_rcu);
}

void stream_put(struct relay_stream *stream)
{
	DBG("stream put for stream id %" PRIu64, stream->stream_handle);
	/*
	 * Ensure existance of stream->reflock for stream unlock.
	 */
	rcu_read_lock();
	/*
	 * Stream reflock ensures that concurrent test and update of
	 * stream ref is atomic.
	 */
	pthread_mutex_lock(&stream->reflock);
	assert(stream->ref.refcount != 0);
	/*
	 * Wait until we have processed all the stream packets before
	 * actually putting our last stream reference.
	 */
	DBG("stream put stream id %" PRIu64 " refcount %d",
		stream->stream_handle,
		(int) stream->ref.refcount);
	urcu_ref_put(&stream->ref, stream_release);
	pthread_mutex_unlock(&stream->reflock);
	rcu_read_unlock();
}

void stream_close(struct relay_stream *stream)
{
	DBG("closing stream %" PRIu64, stream->stream_handle);
	relay_index_close_all(stream);
	stream_put(stream);
}

void print_relay_streams(void)
{
	struct lttng_ht_iter iter;
	struct relay_stream *stream;

	rcu_read_lock();
	cds_lfht_for_each_entry(relay_streams_ht->ht, &iter.iter, stream,
			node.node) {
		if (!stream_get(stream)) {
			continue;
		}
		DBG("stream %p refcount %ld stream %" PRIu64 " trace %" PRIu64
			" session %" PRIu64,
			stream,
			stream->ref.refcount,
			stream->stream_handle,
			stream->trace->id,
			stream->trace->session->id);
		stream_put(stream);
	}
	rcu_read_unlock();
}
