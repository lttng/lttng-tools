/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <common/sessiond-comm/relayd.h>
#include <urcu/rculist.h>
#include <sys/stat.h>

#include "lttng-relayd.h"
#include "index.h"
#include "stream.h"
#include "viewer-stream.h"

#include <sys/types.h>
#include <fcntl.h>

#define FILE_IO_STACK_BUFFER_SIZE		65536

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

static void stream_complete_rotation(struct relay_stream *stream)
{
	DBG("Rotation completed for stream %" PRIu64, stream->stream_handle);
	lttng_trace_chunk_put(stream->trace_chunk);
	stream->trace_chunk = stream->ongoing_rotation.value.next_trace_chunk;
	stream->ongoing_rotation = (typeof(stream->ongoing_rotation)) {};
}

static int stream_create_data_output_file_from_trace_chunk(
		struct relay_stream *stream,
		struct lttng_trace_chunk *trace_chunk,
		bool force_unlink,
		struct stream_fd **out_stream_fd)
{
	int ret, fd;
	char stream_path[LTTNG_PATH_MAX];
	enum lttng_trace_chunk_status status;
	const int flags = O_RDWR | O_CREAT | O_TRUNC;
	const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	ASSERT_LOCKED(stream->lock);
	assert(stream->trace_chunk);

	ret = utils_stream_file_path(stream->path_name, stream->channel_name,
			stream->tracefile_size, stream->tracefile_current_index,
			NULL, stream_path, sizeof(stream_path));
	if (ret < 0) {
		goto end;
	}

	if (stream->tracefile_wrapped_around || force_unlink) {
		/*
		 * The on-disk ring-buffer has wrapped around.
		 * Newly created stream files will replace existing files. Since
		 * live clients may be consuming existing files, the file about
		 * to be replaced is unlinked in order to not overwrite its
		 * content.
		 */
		status = lttng_trace_chunk_unlink_file(trace_chunk,
				stream_path);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			PERROR("Failed to unlink stream file \"%s\" during trace file rotation",
					stream_path);
			/*
			 * Don't abort if the file doesn't exist, it is
			 * unexpected, but should not be a fatal error.
			 */
			if (errno != ENOENT) {
				ret = -1;
				goto end;
			}
		}
	}

	status = lttng_trace_chunk_open_file(
			trace_chunk, stream_path, flags, mode, &fd);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ERR("Failed to open stream file \"%s\"", stream->channel_name);
		ret = -1;
		goto end;
	}

	*out_stream_fd = stream_fd_create(fd);
	if (!*out_stream_fd) {
		if (close(ret)) {
			PERROR("Error closing stream file descriptor %d", ret);
		}
		ret = -1;
		goto end;
	}
end:
	return ret;
}

static int stream_rotate_data_file(struct relay_stream *stream)
{
	int ret = 0;

	DBG("Rotating stream %" PRIu64 " data file",
			stream->stream_handle);

	if (stream->stream_fd) {
		stream_fd_put(stream->stream_fd);
		stream->stream_fd = NULL;
	}

	stream->tracefile_wrapped_around = false;
	stream->tracefile_current_index = 0;

	if (stream->ongoing_rotation.value.next_trace_chunk) {
		struct stream_fd *new_stream_fd = NULL;
		enum lttng_trace_chunk_status chunk_status;

		chunk_status = lttng_trace_chunk_create_subdirectory(
				stream->ongoing_rotation.value.next_trace_chunk,
				stream->path_name);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			goto end;
		}

		/* Rotate the data file. */
		ret = stream_create_data_output_file_from_trace_chunk(stream,
				stream->ongoing_rotation.value.next_trace_chunk,
				false, &new_stream_fd);
		stream->stream_fd = new_stream_fd;
		if (ret < 0) {
			ERR("Failed to rotate stream data file");
			goto end;
		}
	}
	stream->tracefile_size_current = 0;
	stream->pos_after_last_complete_data_index = 0;
	stream->ongoing_rotation.value.data_rotated = true;

	if (stream->ongoing_rotation.value.index_rotated) {
		/* Rotation completed; reset its state. */
		stream_complete_rotation(stream);
	}
end:
	return ret;
}

/*
 * If too much data has been written in a tracefile before we received the
 * rotation command, we have to move the excess data to the new tracefile and
 * perform the rotation. This can happen because the control and data
 * connections are separate, the indexes as well as the commands arrive from
 * the control connection and we have no control over the order so we could be
 * in a situation where too much data has been received on the data connection
 * before the rotation command on the control connection arrives.
 */
static int rotate_truncate_stream(struct relay_stream *stream)
{
	int ret;
	off_t lseek_ret, previous_stream_copy_origin;
	uint64_t copy_bytes_left, misplaced_data_size;
	bool acquired_reference;
	struct stream_fd *previous_stream_fd = NULL;
	struct lttng_trace_chunk *previous_chunk = NULL;

	if (!LTTNG_OPTIONAL_GET(&stream->ongoing_rotation)->next_trace_chunk) {
		ERR("Protocol error encoutered in %s(): stream rotation "
			"sequence number is before the current sequence number "
			"and the next trace chunk is unset. Honoring this "
			"rotation command would result in data loss",
				__FUNCTION__);
		ret = -1;
		goto end;
	}

	ASSERT_LOCKED(stream->lock);
	/*
	 * Acquire a reference to the current trace chunk to ensure
	 * it is not reclaimed when `stream_rotate_data_file` is called.
	 * Failing to do so would violate the contract of the trace
	 * chunk API as an active file descriptor would outlive the
	 * trace chunk.
	 */
	acquired_reference = lttng_trace_chunk_get(stream->trace_chunk);
	assert(acquired_reference);
	previous_chunk = stream->trace_chunk;

	/*
	 * Steal the stream's reference to its stream_fd. A new
	 * stream_fd will be created when the rotation completes and
	 * the orinal stream_fd will be used to copy the "extra" data
	 * to the new file.
	 */
	assert(stream->stream_fd);
	previous_stream_fd = stream->stream_fd;
	stream->stream_fd = NULL;

	assert(!stream->is_metadata);
	assert(stream->tracefile_size_current >
			stream->pos_after_last_complete_data_index);
	misplaced_data_size = stream->tracefile_size_current -
			      stream->pos_after_last_complete_data_index;
	copy_bytes_left = misplaced_data_size;
	previous_stream_copy_origin = stream->pos_after_last_complete_data_index;

	ret = stream_rotate_data_file(stream);
	if (ret) {
		goto end;
	}

	assert(stream->stream_fd);
	/*
	 * Seek the current tracefile to the position at which the rotation
	 * should have occurred.
	 */
	lseek_ret = lseek(previous_stream_fd->fd, previous_stream_copy_origin,
			SEEK_SET);
	if (lseek_ret < 0) {
		PERROR("Failed to seek to offset %" PRIu64
		       " while copying extra data received before a stream rotation",
				(uint64_t) previous_stream_copy_origin);
		ret = -1;
		goto end;
	}

	/* Move data from the old file to the new file. */
	while (copy_bytes_left) {
		ssize_t io_ret;
		char copy_buffer[FILE_IO_STACK_BUFFER_SIZE];
		const off_t copy_size_this_pass = min_t(
				off_t, copy_bytes_left, sizeof(copy_buffer));

		io_ret = lttng_read(previous_stream_fd->fd, copy_buffer,
				copy_size_this_pass);
		if (io_ret < (ssize_t) copy_size_this_pass) {
			if (io_ret == -1) {
				PERROR("Failed to read %" PRIu64
				       " bytes from fd %i in %s(), returned %zi",
						copy_size_this_pass,
						previous_stream_fd->fd,
						__FUNCTION__, io_ret);
			} else {
				ERR("Failed to read %" PRIu64
				    " bytes from fd %i in %s(), returned %zi",
						copy_size_this_pass,
						previous_stream_fd->fd,
						__FUNCTION__, io_ret);
			}
			ret = -1;
			goto end;
		}

		io_ret = lttng_write(stream->stream_fd->fd, copy_buffer,
				copy_size_this_pass);
		if (io_ret < (ssize_t) copy_size_this_pass) {
			if (io_ret == -1) {
				PERROR("Failed to write %" PRIu64
				       " bytes from fd %i in %s(), returned %zi",
						copy_size_this_pass,
						stream->stream_fd->fd,
						__FUNCTION__, io_ret);
			} else {
				ERR("Failed to write %" PRIu64
				    " bytes from fd %i in %s(), returned %zi",
						copy_size_this_pass,
						stream->stream_fd->fd,
						__FUNCTION__, io_ret);
			}
			ret = -1;
			goto end;
		}
		copy_bytes_left -= copy_size_this_pass;
	}

	/* Truncate the file to get rid of the excess data. */
	ret = ftruncate(previous_stream_fd->fd, previous_stream_copy_origin);
	if (ret) {
		PERROR("Failed to truncate current stream file to offset %" PRIu64,
				previous_stream_copy_origin);
		goto end;
	}

	/*
	 * Update the offset and FD of all the eventual indexes created by the
	 * data connection before the rotation command arrived.
	 */
	ret = relay_index_switch_all_files(stream);
	if (ret < 0) {
		ERR("Failed to rotate index file");
		goto end;
	}

	stream->tracefile_size_current = misplaced_data_size;
	/* Index and data contents are back in sync. */
	stream->pos_after_last_complete_data_index = 0;
	ret = 0;
end:
	lttng_trace_chunk_put(previous_chunk);
	stream_fd_put(previous_stream_fd);
	return ret;
}

/*
 * Check if a stream's data file (as opposed to index) should be rotated
 * (for session rotation).
 * Must be called with the stream lock held.
 *
 * Return 0 on success, a negative value on error.
 */
static int try_rotate_stream_data(struct relay_stream *stream)
{
	int ret = 0;

	if (caa_likely(!stream->ongoing_rotation.is_set)) {
		/* No rotation expected. */
		goto end;
	}

	if (stream->ongoing_rotation.value.data_rotated) {
		/* Rotation of the data file has already occurred. */
		goto end;
	}

	if (stream->prev_data_seq == -1ULL ||
			stream->prev_data_seq + 1 < stream->ongoing_rotation.value.seq_num) {
		/*
		 * The next packet that will be written is not part of the next
		 * chunk yet.
		 */
		DBG("Stream %" PRIu64 " not yet ready for rotation (rotate_at_seq_num = %" PRIu64
				", prev_data_seq = %" PRIu64 ")",
				stream->stream_handle,
				stream->ongoing_rotation.value.seq_num,
				stream->prev_data_seq);
		goto end;
	} else if (stream->prev_data_seq > stream->ongoing_rotation.value.seq_num) {
		/*
		 * prev_data_seq is checked here since indexes and rotation
		 * commands are serialized with respect to each other.
		 */
		DBG("Rotation after too much data has been written in tracefile "
				"for stream %" PRIu64 ", need to truncate before "
				"rotating", stream->stream_handle);
		ret = rotate_truncate_stream(stream);
		if (ret) {
			ERR("Failed to truncate stream");
			goto end;
		}
	} else {
		ret = stream_rotate_data_file(stream);
	}

end:
	return ret;
}

/*
 * Close the current index file if it is open, and create a new one.
 *
 * Return 0 on success, -1 on error.
 */
static int create_index_file(struct relay_stream *stream,
		struct lttng_trace_chunk *chunk)
{
	int ret;
	uint32_t major, minor;
	char *index_subpath = NULL;
	enum lttng_trace_chunk_status status;

	ASSERT_LOCKED(stream->lock);

	/* Put ref on previous index_file. */
	if (stream->index_file) {
		lttng_index_file_put(stream->index_file);
		stream->index_file = NULL;
	}
	major = stream->trace->session->major;
	minor = stream->trace->session->minor;

	if (!chunk) {
		ret = 0;
		goto end;
	}
	ret = asprintf(&index_subpath, "%s/%s", stream->path_name,
			DEFAULT_INDEX_DIR);
	if (ret < 0) {
		goto end;
	}

	status = lttng_trace_chunk_create_subdirectory(chunk,
			index_subpath);
	free(index_subpath);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end;
	}
	stream->index_file = lttng_index_file_create_from_trace_chunk(
			chunk, stream->path_name,
			stream->channel_name, stream->tracefile_size,
			stream->tracefile_current_index,
			lttng_to_index_major(major, minor),
			lttng_to_index_minor(major, minor), true);
	if (!stream->index_file) {
		ret = -1;
		goto end;
	}

	ret = 0;

end:
	return ret;
}

/*
 * Check if a stream's index file should be rotated (for session rotation).
 * Must be called with the stream lock held.
 *
 * Return 0 on success, a negative value on error.
 */
static int try_rotate_stream_index(struct relay_stream *stream)
{
	int ret = 0;

	if (!stream->ongoing_rotation.is_set) {
		/* No rotation expected. */
		goto end;
	}

	if (stream->ongoing_rotation.value.index_rotated) {
		/* Rotation of the index has already occurred. */
		goto end;
	}

	if (stream->prev_index_seq == -1ULL ||
			stream->prev_index_seq + 1 < stream->ongoing_rotation.value.seq_num) {
		DBG("Stream %" PRIu64 " index not yet ready for rotation (rotate_at_seq_num = %" PRIu64 ", prev_index_seq = %" PRIu64 ")",
				stream->stream_handle,
				stream->ongoing_rotation.value.seq_num,
				stream->prev_index_seq);
		goto end;
	} else {
		/* The next index belongs to the new trace chunk; rotate. */
		assert(stream->prev_index_seq + 1 ==
				stream->ongoing_rotation.value.seq_num);
		DBG("Rotating stream %" PRIu64 " index file",
				stream->stream_handle);
		ret = create_index_file(stream,
				stream->ongoing_rotation.value.next_trace_chunk);
		stream->ongoing_rotation.value.index_rotated = true;

		if (stream->ongoing_rotation.value.data_rotated &&
				stream->ongoing_rotation.value.index_rotated) {
			/* Rotation completed; reset its state. */
			DBG("Rotation completed for stream %" PRIu64,
					stream->stream_handle);
			stream_complete_rotation(stream);
		}
	}

end:
	return ret;
}

static int stream_set_trace_chunk(struct relay_stream *stream,
		struct lttng_trace_chunk *chunk)
{
	int ret = 0;
	enum lttng_trace_chunk_status status;
	bool acquired_reference;
	struct stream_fd *new_stream_fd = NULL;

	status = lttng_trace_chunk_create_subdirectory(chunk,
			stream->path_name);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end;
	}

	lttng_trace_chunk_put(stream->trace_chunk);
	acquired_reference = lttng_trace_chunk_get(chunk);
	assert(acquired_reference);
	stream->trace_chunk = chunk;

	if (stream->stream_fd) {
		stream_fd_put(stream->stream_fd);
		stream->stream_fd = NULL;
	}
	ret = stream_create_data_output_file_from_trace_chunk(stream, chunk,
			false, &new_stream_fd);
	stream->stream_fd = new_stream_fd;
end:
	return ret;
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
	bool acquired_reference = false;
	struct lttng_trace_chunk *current_trace_chunk;

	stream = zmalloc(sizeof(struct relay_stream));
	if (stream == NULL) {
		PERROR("relay stream zmalloc");
		goto error_no_alloc;
	}

	stream->stream_handle = stream_handle;
	stream->prev_data_seq = -1ULL;
	stream->prev_index_seq = -1ULL;
	stream->last_net_seq_num = -1ULL;
	stream->ctf_stream_id = -1ULL;
	stream->tracefile_size = tracefile_size;
	stream->tracefile_count = tracefile_count;
	stream->path_name = path_name;
	stream->channel_name = channel_name;
	stream->beacon_ts_end = -1ULL;
	lttng_ht_node_init_u64(&stream->node, stream->stream_handle);
	pthread_mutex_init(&stream->lock, NULL);
	urcu_ref_init(&stream->ref);
	ctf_trace_get(trace);
	stream->trace = trace;

	pthread_mutex_lock(&trace->session->lock);
	current_trace_chunk = trace->session->current_trace_chunk;
	if (current_trace_chunk) {
		acquired_reference = lttng_trace_chunk_get(current_trace_chunk);
	}
	pthread_mutex_unlock(&trace->session->lock);
	if (!acquired_reference) {
		ERR("Cannot create stream for channel \"%s\" as a reference to the session's current trace chunk could not be acquired",
				channel_name);
		ret = -1;
		goto end;
	}

	stream->indexes_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!stream->indexes_ht) {
		ERR("Cannot created indexes_ht");
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&stream->lock);
	ret = stream_set_trace_chunk(stream, current_trace_chunk);
	pthread_mutex_unlock(&stream->lock);
	if (ret) {
		ERR("Failed to set the current trace chunk of session \"%s\" on newly created stream of channel \"%s\"",
				trace->session->session_name,
				stream->channel_name);
		ret = -1;
		goto end;
	}
	stream->tfa = tracefile_array_create(stream->tracefile_count);
	if (!stream->tfa) {
		ret = -1;
		goto end;
	}

	stream->is_metadata = !strcmp(stream->channel_name,
			DEFAULT_METADATA_NAME);
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
	if (acquired_reference) {
		lttng_trace_chunk_put(current_trace_chunk);
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
	stream_complete_rotation(stream);
	lttng_trace_chunk_put(stream->trace_chunk);
	stream->trace_chunk = NULL;

	call_rcu(&stream->rcu_node, stream_destroy_rcu);
}

void stream_put(struct relay_stream *stream)
{
	rcu_read_lock();
	assert(stream->ref.refcount != 0);
	/*
	 * Wait until we have processed all the stream packets before
	 * actually putting our last stream reference.
	 */
	urcu_ref_put(&stream->ref, stream_release);
	rcu_read_unlock();
}

int stream_set_pending_rotation(struct relay_stream *stream,
		struct lttng_trace_chunk *next_trace_chunk,
		uint64_t rotation_sequence_number)
{
	int ret = 0;
	const struct relay_stream_rotation rotation = {
		.seq_num = rotation_sequence_number,
		.next_trace_chunk = next_trace_chunk,
	};

	if (stream->ongoing_rotation.is_set) {
		ERR("Attempted to set a pending rotation on a stream already being rotated (protocol error)");
		ret = -1;
		goto end;
	}

	if (next_trace_chunk) {
		const bool reference_acquired =
				lttng_trace_chunk_get(next_trace_chunk);

		assert(reference_acquired);
	}
	LTTNG_OPTIONAL_SET(&stream->ongoing_rotation, rotation);

	DBG("Setting pending rotation: stream_id = %" PRIu64 ", rotation_seq_num = %" PRIu64,
			stream->stream_handle, rotation_sequence_number);
	if (stream->is_metadata) {
		/*
		 * A metadata stream has no index; consider it already rotated.
		 */
		stream->ongoing_rotation.value.index_rotated = true;
		ret = stream_rotate_data_file(stream);
	} else {
		ret = try_rotate_stream_data(stream);
		if (ret < 0) {
			goto end;
		}

		ret = try_rotate_stream_index(stream);
		if (ret < 0) {
			goto end;
		}
	}
end:
	return ret;
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
		DBG("relay_index_close_partial_fd");
		relay_index_close_partial_fd(stream);
		/*
		 * Use the highest net_seq_num we currently have pending
		 * As end of stream indicator.  Leave last_net_seq_num
		 * at -1ULL if we cannot find any index.
		 */
		stream->last_net_seq_num = relay_index_find_last(stream);
		DBG("Updating stream->last_net_seq_num to %" PRIu64, stream->last_net_seq_num);
		/* Fall-through into the next check. */
	}

	if (stream->last_net_seq_num != -1ULL &&
			((int64_t) (stream->prev_data_seq - stream->last_net_seq_num)) < 0
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

int stream_init_packet(struct relay_stream *stream, size_t packet_size,
		bool *file_rotated)
{
	int ret = 0;

	ASSERT_LOCKED(stream->lock);
	if (caa_likely(stream->tracefile_size == 0)) {
		/* No size limit set; nothing to check. */
		goto end;
	}

	/*
	 * Check if writing the new packet would exceed the maximal file size.
	 */
	if (caa_unlikely((stream->tracefile_size_current + packet_size) >
			stream->tracefile_size)) {
		const uint64_t new_file_index =
				(stream->tracefile_current_index + 1) %
				stream->tracefile_count;

		if (new_file_index < stream->tracefile_current_index) {
			stream->tracefile_wrapped_around = true;
		}
		DBG("New stream packet causes stream file rotation: stream_id = %" PRIu64
				", current_file_size = %" PRIu64
				", packet_size = %zu, current_file_index = %" PRIu64
				" new_file_index = %" PRIu64,
				stream->stream_handle,
				stream->tracefile_size_current, packet_size,
				stream->tracefile_current_index, new_file_index);
		tracefile_array_file_rotate(stream->tfa);
		stream->tracefile_current_index = new_file_index;

		if (stream->stream_fd) {
			stream_fd_put(stream->stream_fd);
			stream->stream_fd = NULL;
		}
		ret = stream_create_data_output_file_from_trace_chunk(stream,
				stream->trace_chunk, false, &stream->stream_fd);
		if (ret) {
			ERR("Failed to perform trace file rotation of stream %" PRIu64,
					stream->stream_handle);
			goto end;
		}

		/*
		 * Reset current size because we just performed a stream
		 * rotation.
		 */
		stream->tracefile_size_current = 0;
		*file_rotated = true;
	} else {
		*file_rotated = false;
	}
end:
	return ret;
}

/* Note that the packet is not necessarily complete. */
int stream_write(struct relay_stream *stream,
		const struct lttng_buffer_view *packet, size_t padding_len)
{
	int ret = 0;
	ssize_t write_ret;
	size_t padding_to_write = padding_len;
	char padding_buffer[FILE_IO_STACK_BUFFER_SIZE];

	ASSERT_LOCKED(stream->lock);
	memset(padding_buffer, 0,
			min(sizeof(padding_buffer), padding_to_write));

	if (packet) {
		write_ret = lttng_write(stream->stream_fd->fd,
				packet->data, packet->size);
		if (write_ret != packet->size) {
			PERROR("Failed to write to stream file of %sstream %" PRIu64,
					stream->is_metadata ? "metadata " : "",
					stream->stream_handle);
			ret = -1;
			goto end;
		}
	}

	while (padding_to_write > 0) {
		const size_t padding_to_write_this_pass =
				min(padding_to_write, sizeof(padding_buffer));

		write_ret = lttng_write(stream->stream_fd->fd,
				padding_buffer, padding_to_write_this_pass);
		if (write_ret != padding_to_write_this_pass) {
			PERROR("Failed to write padding to file of %sstream %" PRIu64,
					stream->is_metadata ? "metadata " : "",
					stream->stream_handle);
			ret = -1;
			goto end;
		}
		padding_to_write -= padding_to_write_this_pass;
	}

	if (stream->is_metadata) {
		stream->metadata_received += packet ? packet->size : 0;
		stream->metadata_received += padding_len;
	}

	DBG("Wrote to %sstream %" PRIu64 ": data_length = %zu, padding_length = %zu",
			stream->is_metadata ? "metadata " : "",
			stream->stream_handle,
			packet ? packet->size : (size_t) 0, padding_len);
end:
	return ret;
}

/*
 * Update index after receiving a packet for a data stream.
 *
 * Called with the stream lock held.
 *
 * Return 0 on success else a negative value.
 */
int stream_update_index(struct relay_stream *stream, uint64_t net_seq_num,
		bool rotate_index, bool *flushed, uint64_t total_size)
{
	int ret = 0;
	uint64_t data_offset;
	struct relay_index *index;

	assert(stream->trace_chunk);
	ASSERT_LOCKED(stream->lock);
	/* Get data offset because we are about to update the index. */
	data_offset = htobe64(stream->tracefile_size_current);

	DBG("handle_index_data: stream %" PRIu64 " net_seq_num %" PRIu64 " data offset %" PRIu64,
			stream->stream_handle, net_seq_num, stream->tracefile_size_current);

	/*
	 * Lookup for an existing index for that stream id/sequence
	 * number. If it exists, the control thread has already received the
	 * data for it, thus we need to write it to disk.
	 */
	index = relay_index_get_by_id_or_create(stream, net_seq_num);
	if (!index) {
		ret = -1;
		goto end;
	}

	if (rotate_index || !stream->index_file) {
		ret = create_index_file(stream, stream->trace_chunk);
		if (ret) {
			ERR("Failed to create index file for stream %" PRIu64,
					stream->stream_handle);
			/* Put self-ref for this index due to error. */
			relay_index_put(index);
			index = NULL;
			goto end;
		}
	}

	if (relay_index_set_file(index, stream->index_file, data_offset)) {
		ret = -1;
		/* Put self-ref for this index due to error. */
		relay_index_put(index);
		index = NULL;
		goto end;
	}

	ret = relay_index_try_flush(index);
	if (ret == 0) {
		tracefile_array_commit_seq(stream->tfa);
		stream->index_received_seqcount++;
		*flushed = true;
	} else if (ret > 0) {
		index->total_size = total_size;
		/* No flush. */
		ret = 0;
	} else {
		/*
		 * ret < 0
		 *
		 * relay_index_try_flush is responsible for the self-reference
		 * put of the index object on error.
		 */
		ERR("relay_index_try_flush error %d", ret);
		ret = -1;
	}
end:
	return ret;
}

int stream_complete_packet(struct relay_stream *stream, size_t packet_total_size,
		uint64_t sequence_number, bool index_flushed)
{
	int ret = 0;

	ASSERT_LOCKED(stream->lock);

	stream->tracefile_size_current += packet_total_size;
	if (index_flushed) {
		stream->pos_after_last_complete_data_index =
				stream->tracefile_size_current;
		stream->prev_index_seq = sequence_number;
		ret = try_rotate_stream_index(stream);
		if (ret < 0) {
			goto end;
		}
	}

	stream->prev_data_seq = sequence_number;
	ret = try_rotate_stream_data(stream);

end:
	return ret;
}

int stream_add_index(struct relay_stream *stream,
		const struct lttcomm_relayd_index *index_info)
{
	int ret = 0;
	struct relay_index *index;

	ASSERT_LOCKED(stream->lock);

	/* Live beacon handling */
	if (index_info->packet_size == 0) {
		DBG("Received live beacon for stream %" PRIu64,
				stream->stream_handle);

		/*
		 * Only flag a stream inactive when it has already
		 * received data and no indexes are in flight.
		 */
		if (stream->index_received_seqcount > 0
				&& stream->indexes_in_flight == 0) {
			stream->beacon_ts_end = index_info->timestamp_end;
		}
		ret = 0;
		goto end;
	} else {
		stream->beacon_ts_end = -1ULL;
	}

	if (stream->ctf_stream_id == -1ULL) {
		stream->ctf_stream_id = index_info->stream_id;
	}

	index = relay_index_get_by_id_or_create(stream, index_info->net_seq_num);
	if (!index) {
		ret = -1;
		ERR("Failed to get or create index %" PRIu64,
				index_info->net_seq_num);
		goto end;
	}
	if (relay_index_set_control_data(index, index_info,
			stream->trace->session->minor)) {
		ERR("set_index_control_data error");
		relay_index_put(index);
		ret = -1;
		goto end;
	}
	ret = relay_index_try_flush(index);
	if (ret == 0) {
		tracefile_array_commit_seq(stream->tfa);
		stream->index_received_seqcount++;
		stream->pos_after_last_complete_data_index += index->total_size;
		stream->prev_index_seq = index_info->net_seq_num;

		ret = try_rotate_stream_index(stream);
		if (ret < 0) {
			goto end;
		}
	} else if (ret > 0) {
		/* no flush. */
		ret = 0;
	} else {
		/*
		 * ret < 0
		 *
		 * relay_index_try_flush is responsible for the self-reference
		 * put of the index object on error.
		 */
		ERR("relay_index_try_flush error %d", ret);
		ret = -1;
	}
end:
	return ret;
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

int stream_reset_file(struct relay_stream *stream)
{
	ASSERT_LOCKED(stream->lock);

	if (stream->stream_fd) {
		stream_fd_put(stream->stream_fd);
		stream->stream_fd = NULL;
	}

	stream->tracefile_size_current = 0;
	stream->prev_data_seq = 0;
	stream->prev_index_seq = 0;
	/* Note that this does not reset the tracefile array. */
	stream->tracefile_current_index = 0;
	stream->pos_after_last_complete_data_index = 0;

	return stream_create_data_output_file_from_trace_chunk(stream,
			stream->trace_chunk, true, &stream->stream_fd);
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
