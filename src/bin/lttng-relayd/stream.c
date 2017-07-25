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
	return urcu_ref_get_unless_zero(&stream->ref);
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
		goto error_no_alloc;
	}

	stream->stream_handle = stream_handle;
	stream->prev_seq = -1ULL;
	stream->last_net_seq_num = -1ULL;
	stream->ctf_stream_id = -1ULL;
	stream->tracefile_size = tracefile_size;
	stream->tracefile_count = tracefile_count;
	stream->path_name = path_name;
	stream->channel_name = channel_name;
	lttng_ht_node_init_u64(&stream->node, stream->stream_handle);
	pthread_mutex_init(&stream->lock, NULL);
	urcu_ref_init(&stream->ref);
	ctf_trace_get(trace);
	stream->trace = trace;

	stream->indexes_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!stream->indexes_ht) {
		ERR("Cannot created indexes_ht");
		ret = -1;
		goto end;
	}

	ret = utils_mkdir_recursive(stream->path_name, S_IRWXU | S_IRWXG,
			-1, -1);
	if (ret < 0) {
		ERR("relay creating output directory");
		goto end;
	}

	/*
	 * No need to use run_as API here because whatever we receive,
	 * the relayd uses its own credentials for the stream files.
	 */
	ret = utils_create_stream_file(stream->path_name, stream->channel_name,
			stream->tracefile_size, 0, -1, -1, NULL);
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
	stream->tfa = tracefile_array_create(stream->tracefile_count);
	if (!stream->tfa) {
		ret = -1;
		goto end;
	}
	if (stream->tracefile_size) {
		DBG("Tracefile %s/%s_0 created", stream->path_name, stream->channel_name);
	} else {
		DBG("Tracefile %s/%s created", stream->path_name, stream->channel_name);
	}

	if (!strncmp(stream->channel_name, DEFAULT_METADATA_NAME, LTTNG_NAME_MAX)) {
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
	stream->in_stream_ht = true;

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
 * Stream must be protected by holding the stream lock or by virtue of being
 * called from stream_destroy.
 */
static void stream_unpublish(struct relay_stream *stream)
{
	if (stream->in_stream_ht) {
		struct lttng_ht_iter iter;
		int ret;

		iter.iter.node = &stream->node.node;
		ret = lttng_ht_del(relay_streams_ht, &iter);
		assert(!ret);
		stream->in_stream_ht = false;
	}
	if (stream->published) {
		pthread_mutex_lock(&stream->trace->stream_list_lock);
		cds_list_del_rcu(&stream->stream_node);
		pthread_mutex_unlock(&stream->trace->stream_list_lock);
		stream->published = false;
	}
}

static void stream_destroy(struct relay_stream *stream)
{
	if (stream->indexes_ht) {
		/*
		 * Calling lttng_ht_destroy in call_rcu worker thread so
		 * we don't hold the RCU read-side lock while calling
		 * it.
		 */
		lttng_ht_destroy(stream->indexes_ht);
	}
	if (stream->tfa) {
		tracefile_array_destroy(stream->tfa);
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

/*
 * No need to take stream->lock since this is only called on the final
 * stream_put which ensures that a single thread may act on the stream.
 */
static void stream_release(struct urcu_ref *ref)
{
	struct relay_stream *stream =
		caa_container_of(ref, struct relay_stream, ref);
	struct relay_session *session;

	session = stream->trace->session;

	DBG("Releasing stream id %" PRIu64, stream->stream_handle);

	pthread_mutex_lock(&session->recv_list_lock);
	session->stream_count--;
	if (stream->in_recv_list) {
		cds_list_del_rcu(&stream->recv_node);
		stream->in_recv_list = false;
	}
	pthread_mutex_unlock(&session->recv_list_lock);

	stream_unpublish(stream);

	if (stream->stream_fd) {
		stream_fd_put(stream->stream_fd);
		stream->stream_fd = NULL;
	}
	if (stream->index_file) {
		lttng_index_file_put(stream->index_file);
		stream->index_file = NULL;
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
	rcu_read_lock();
	assert(stream->ref.refcount != 0);
	/*
	 * Wait until we have processed all the stream packets before
	 * actually putting our last stream reference.
	 */
	DBG("stream put stream id %" PRIu64 " refcount %d",
			stream->stream_handle,
			(int) stream->ref.refcount);
	urcu_ref_put(&stream->ref, stream_release);
	rcu_read_unlock();
}

void try_stream_close(struct relay_stream *stream)
{
	bool session_aborted;
	struct relay_session *session = stream->trace->session;

	DBG("Trying to close stream %" PRIu64, stream->stream_handle);

	pthread_mutex_lock(&session->lock);
	session_aborted = session->aborted;
	pthread_mutex_unlock(&session->lock);

	pthread_mutex_lock(&stream->lock);
	/*
	 * Can be called concurently by connection close and reception of last
	 * pending data.
	 */
	if (stream->closed) {
		pthread_mutex_unlock(&stream->lock);
		DBG("closing stream %" PRIu64 " aborted since it is already marked as closed", stream->stream_handle);
		return;
	}

	stream->close_requested = true;

	if (stream->last_net_seq_num == -1ULL) {
		/*
		 * Handle connection close without explicit stream close
		 * command.
		 *
		 * We can be clever about indexes partially received in
		 * cases where we received the data socket part, but not
		 * the control socket part: since we're currently closing
		 * the stream on behalf of the control socket, we *know*
		 * there won't be any more control information for this
		 * socket. Therefore, we can destroy all indexes for
		 * which we have received only the file descriptor (from
		 * data socket). This takes care of consumerd crashes
		 * between sending the data and control information for
		 * a packet. Since those are sent in that order, we take
		 * care of consumerd crashes.
		 */
		relay_index_close_partial_fd(stream);
		/*
		 * Use the highest net_seq_num we currently have pending
		 * As end of stream indicator.  Leave last_net_seq_num
		 * at -1ULL if we cannot find any index.
		 */
		stream->last_net_seq_num = relay_index_find_last(stream);
		/* Fall-through into the next check. */
	}

	if (stream->last_net_seq_num != -1ULL &&
			((int64_t) (stream->prev_seq - stream->last_net_seq_num)) < 0
			&& !session_aborted) {
		/*
		 * Don't close since we still have data pending. This
		 * handles cases where an explicit close command has
		 * been received for this stream, and cases where the
		 * connection has been closed, and we are awaiting for
		 * index information from the data socket. It is
		 * therefore expected that all the index fd information
		 * we need has already been received on the control
		 * socket. Matching index information from data socket
		 * should be Expected Soon(TM).
		 *
		 * TODO: We should implement a timer to garbage collect
		 * streams after a timeout to be resilient against a
		 * consumerd implementation that would not match this
		 * expected behavior.
		 */
		pthread_mutex_unlock(&stream->lock);
		DBG("closing stream %" PRIu64 " aborted since it still has data pending", stream->stream_handle);
		return;
	}
	/*
	 * We received all the indexes we can expect.
	 */
	stream_unpublish(stream);
	stream->closed = true;
	/* Relay indexes are only used by the "consumer/sessiond" end. */
	relay_index_close_all(stream);
	pthread_mutex_unlock(&stream->lock);
	DBG("Succeeded in closing stream %" PRIu64, stream->stream_handle);
	stream_put(stream);
}

static void print_stream_indexes(struct relay_stream *stream)
{
	struct lttng_ht_iter iter;
	struct relay_index *index;

	rcu_read_lock();
	cds_lfht_for_each_entry(stream->indexes_ht->ht, &iter.iter, index,
			index_n.node) {
		DBG("index %p net_seq_num %" PRIu64 " refcount %ld"
				" stream %" PRIu64 " trace %" PRIu64
				" session %" PRIu64,
				index,
				index->index_n.key,
				stream->ref.refcount,
				index->stream->stream_handle,
				index->stream->trace->id,
				index->stream->trace->session->id);
	}
	rcu_read_unlock();
}

void print_relay_streams(void)
{
	struct lttng_ht_iter iter;
	struct relay_stream *stream;

	if (!relay_streams_ht) {
		return;
	}

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
		print_stream_indexes(stream);
		stream_put(stream);
	}
	rcu_read_unlock();
}
