/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "lttng-relayd.hpp"
#include "viewer-stream.hpp"

#include <common/common.hpp>
#include <common/compat/string.hpp>
#include <common/index/index.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

static void viewer_stream_release_composite_objects(struct relay_viewer_stream *vstream)
{
	if (vstream->stream_file.handle) {
		fs_handle_close(vstream->stream_file.handle);
		vstream->stream_file.handle = nullptr;
	}
	if (vstream->index_file) {
		lttng_index_file_put(vstream->index_file);
		vstream->index_file = nullptr;
	}
	if (vstream->stream) {
		stream_put(vstream->stream);
		vstream->stream = nullptr;
	}
	lttng_trace_chunk_put(vstream->stream_file.trace_chunk);
	vstream->stream_file.trace_chunk = nullptr;
}

static void viewer_stream_destroy(struct relay_viewer_stream *vstream)
{
	free(vstream->path_name);
	free(vstream->channel_name);
	free(vstream);
}

static void viewer_stream_destroy_rcu(struct rcu_head *head)
{
	struct relay_viewer_stream *vstream =
		lttng::utils::container_of(head, &relay_viewer_stream::rcu_node);

	viewer_stream_destroy(vstream);
}

/* Relay stream's lock must be held by the caller. */
struct relay_viewer_stream *viewer_stream_create(struct relay_stream *stream,
						 struct lttng_trace_chunk *trace_chunk,
						 enum lttng_viewer_seek seek_t)
{
	struct relay_viewer_stream *vstream = nullptr;

	ASSERT_LOCKED(stream->lock);

	vstream = zmalloc<relay_viewer_stream>();
	if (!vstream) {
		PERROR("relay viewer stream zmalloc");
		goto error;
	}

	if (trace_chunk) {
		const bool acquired_reference = lttng_trace_chunk_get(trace_chunk);

		LTTNG_ASSERT(acquired_reference);
	}

	vstream->stream_file.trace_chunk = trace_chunk;
	vstream->path_name = lttng_strndup(stream->path_name, LTTNG_VIEWER_PATH_MAX);
	if (vstream->path_name == nullptr) {
		PERROR("relay viewer path_name alloc");
		goto error;
	}
	vstream->channel_name = lttng_strndup(stream->channel_name, LTTNG_VIEWER_NAME_MAX);
	if (vstream->channel_name == nullptr) {
		PERROR("relay viewer channel_name alloc");
		goto error;
	}

	if (!stream_get(stream)) {
		ERR("Cannot get stream");
		goto error;
	}
	vstream->stream = stream;

	if (stream->is_metadata && stream->trace->viewer_metadata_stream) {
		ERR("Cannot attach viewer metadata stream to trace (busy).");
		goto error;
	}

	switch (seek_t) {
	case LTTNG_VIEWER_SEEK_BEGINNING:
	{
		uint64_t seq_tail = tracefile_array_get_seq_tail(stream->tfa);

		if (seq_tail == -1ULL) {
			/*
			 * Tail may not be initialized yet. Nonetheless, we know
			 * we want to send the first index once it becomes
			 * available.
			 */
			seq_tail = 0;
		}
		vstream->current_tracefile_id = tracefile_array_get_file_index_tail(stream->tfa);
		vstream->index_sent_seqcount = seq_tail;
		break;
	}
	case LTTNG_VIEWER_SEEK_LAST:
		vstream->current_tracefile_id =
			tracefile_array_get_read_file_index_head(stream->tfa);
		/*
		 * We seek at the very end of each stream, awaiting for
		 * a future packet to eventually come in.
		 *
		 * We don't need to check the head position for -1ULL since the
		 * increment will set it to 0.
		 */
		vstream->index_sent_seqcount = tracefile_array_get_seq_head(stream->tfa) + 1;
		break;
	default:
		goto error;
	}

	/*
	 * If we never received an index for the current stream, delay
	 * the opening of the index, otherwise open it right now.
	 */
	if (stream->index_file == nullptr) {
		vstream->index_file = nullptr;
	} else if (vstream->stream_file.trace_chunk) {
		const uint32_t connection_major = stream->trace->session->major;
		const uint32_t connection_minor = stream->trace->session->minor;
		enum lttng_trace_chunk_status chunk_status;

		chunk_status = lttng_index_file_create_from_trace_chunk_read_only(
			vstream->stream_file.trace_chunk,
			stream->path_name,
			stream->channel_name,
			stream->tracefile_size,
			vstream->current_tracefile_id,
			lttng_to_index_major(connection_major, connection_minor),
			lttng_to_index_minor(connection_major, connection_minor),
			true,
			&vstream->index_file);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			if (chunk_status == LTTNG_TRACE_CHUNK_STATUS_NO_FILE) {
				vstream->index_file = nullptr;
			} else {
				goto error;
			}
		}
	}

	/*
	 * If we never received a data file for the current stream, delay the
	 * opening, otherwise open it right now.
	 */
	if (stream->file && vstream->stream_file.trace_chunk) {
		int ret;
		char file_path[LTTNG_PATH_MAX];
		enum lttng_trace_chunk_status status;

		ret = utils_stream_file_path(stream->path_name,
					     stream->channel_name,
					     stream->tracefile_size,
					     vstream->current_tracefile_id,
					     nullptr,
					     file_path,
					     sizeof(file_path));
		if (ret < 0) {
			goto error;
		}

		status = lttng_trace_chunk_open_fs_handle(vstream->stream_file.trace_chunk,
							  file_path,
							  O_RDONLY,
							  0,
							  &vstream->stream_file.handle,
							  true);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			goto error;
		}
	}

	if (seek_t == LTTNG_VIEWER_SEEK_LAST && vstream->index_file) {
		off_t lseek_ret;

		lseek_ret = fs_handle_seek(vstream->index_file->file, 0, SEEK_END);
		if (lseek_ret < 0) {
			goto error;
		}
	}
	if (stream->is_metadata) {
		rcu_assign_pointer(stream->trace->viewer_metadata_stream, vstream);
	}

	vstream->last_seen_rotation_count = stream->completed_rotation_count;

	/* Globally visible after the add unique. */
	lttng_ht_node_init_u64(&vstream->stream_n, stream->stream_handle);
	urcu_ref_init(&vstream->ref);
	lttng_ht_add_unique_u64(viewer_streams_ht, &vstream->stream_n);

	return vstream;

error:
	if (vstream) {
		/* Not using `put` since vstream is assumed to be published. */
		viewer_stream_release_composite_objects(vstream);
		viewer_stream_destroy(vstream);
	}
	return nullptr;
}

static void viewer_stream_unpublish(struct relay_viewer_stream *vstream)
{
	int ret;
	struct lttng_ht_iter iter;

	iter.iter.node = &vstream->stream_n.node;
	ret = lttng_ht_del(viewer_streams_ht, &iter);
	LTTNG_ASSERT(!ret);
}

static void viewer_stream_release(struct urcu_ref *ref)
{
	struct relay_viewer_stream *vstream =
		caa_container_of(ref, struct relay_viewer_stream, ref);

	if (vstream->stream->is_metadata) {
		rcu_assign_pointer(vstream->stream->trace->viewer_metadata_stream, NULL);
	}
	viewer_stream_unpublish(vstream);
	viewer_stream_release_composite_objects(vstream);
	call_rcu(&vstream->rcu_node, viewer_stream_destroy_rcu);
}

/* Must be called with RCU read-side lock held. */
bool viewer_stream_get(struct relay_viewer_stream *vstream)
{
	return urcu_ref_get_unless_zero(&vstream->ref);
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
	struct relay_viewer_stream *vstream = nullptr;

	const lttng::urcu::read_lock_guard read_lock;
	lttng_ht_lookup(viewer_streams_ht, &id, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		DBG("Relay viewer stream %" PRIu64 " not found", id);
		goto end;
	}
	vstream = lttng::utils::container_of(node, &relay_viewer_stream::stream_n);
	if (!viewer_stream_get(vstream)) {
		vstream = nullptr;
	}
end:
	return vstream;
}

void viewer_stream_put(struct relay_viewer_stream *vstream)
{
	const lttng::urcu::read_lock_guard read_lock;
	urcu_ref_put(&vstream->ref, viewer_stream_release);
}

void viewer_stream_close_files(struct relay_viewer_stream *vstream)
{
	if (vstream->index_file) {
		lttng_index_file_put(vstream->index_file);
		vstream->index_file = nullptr;
	}
	if (vstream->stream_file.handle) {
		fs_handle_close(vstream->stream_file.handle);
		vstream->stream_file.handle = nullptr;
	}
}

void viewer_stream_sync_tracefile_array_tail(struct relay_viewer_stream *vstream)
{
	const struct relay_stream *stream = vstream->stream;
	uint64_t seq_tail;

	vstream->current_tracefile_id = tracefile_array_get_file_index_tail(stream->tfa);
	seq_tail = tracefile_array_get_seq_tail(stream->tfa);
	if (seq_tail == -1ULL) {
		seq_tail = 0;
	}

	/*
	 * Move the index sent seqcount forward if it was lagging behind
	 * the new tail of the tracefile array. If the current
	 * index_sent_seqcount is already further than the tracefile
	 * array tail position, keep its current position.
	 */
	vstream->index_sent_seqcount = std::max(seq_tail, vstream->index_sent_seqcount);
}

/*
 * Rotate a stream to the next tracefile.
 *
 * Must be called with the rstream lock held.
 * Returns 0 on success, 1 on EOF.
 */
int viewer_stream_rotate(struct relay_viewer_stream *vstream)
{
	int ret;
	uint64_t new_id;
	const struct relay_stream *stream = vstream->stream;

	/* Detect the last tracefile to open. */
	if (stream->index_received_seqcount == vstream->index_sent_seqcount &&
	    stream->trace->session->connection_closed) {
		ret = 1;
		goto end;
	}

	if (stream->tracefile_count == 0) {
		/* Ignore rotation, there is none to do. */
		ret = 0;
		goto end;
	}

	/*
	 * Try to move to the next file.
	 */
	new_id = (vstream->current_tracefile_id + 1) % stream->tracefile_count;
	if (tracefile_array_seq_in_file(stream->tfa, new_id, vstream->index_sent_seqcount)) {
		vstream->current_tracefile_id = new_id;
	} else {
		const uint64_t seq_tail = tracefile_array_get_seq_tail(stream->tfa);

		/*
		 * This can only be reached on overwrite, which implies there
		 * has been data written at some point, which will have set the
		 * tail.
		 */
		LTTNG_ASSERT(seq_tail != -1ULL);
		/*
		 * We need to resync because we lag behind tail.
		 */
		vstream->current_tracefile_id = tracefile_array_get_file_index_tail(stream->tfa);
		vstream->index_sent_seqcount = seq_tail;
	}
	viewer_stream_close_files(vstream);
	ret = 0;
end:
	return ret;
}

void print_viewer_streams()
{
	struct lttng_ht_iter iter;
	struct relay_viewer_stream *vstream;

	if (!viewer_streams_ht) {
		return;
	}

	{
		const lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			viewer_streams_ht->ht, &iter.iter, vstream, stream_n.node) {
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
	}
}
