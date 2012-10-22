/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <lttng/ust-ctl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <unistd.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/relayd/relayd.h>
#include <common/compat/fcntl.h>

#include "ust-consumer.h"

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;
extern volatile int consumer_quit;

/*
 * Wrapper over the mmap() read offset from ust-ctl library. Since this can be
 * compiled out, we isolate it in this library.
 */
int lttng_ustctl_get_mmap_read_offset(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *off)
{
	return ustctl_get_mmap_read_offset(handle, buf, off);
};

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_ustconsumer_take_snapshot(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream)
{
	int ret = 0;

	ret = ustctl_snapshot(stream->chan->handle, stream->buf);
	if (ret != 0) {
		errno = -ret;
		PERROR("Getting sub-buffer snapshot.");
	}

	return ret;
}

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_ustconsumer_get_produced_snapshot(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream,
		unsigned long *pos)
{
	int ret;

	ret = ustctl_snapshot_get_produced(stream->chan->handle,
			stream->buf, pos);
	if (ret != 0) {
		errno = -ret;
		PERROR("kernctl_snapshot_get_produced");
	}

	return ret;
}

/*
 * Receive command from session daemon and process it.
 *
 * Return 1 on success else a negative value or 0.
 */
int lttng_ustconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll)
{
	ssize_t ret;
	struct lttcomm_consumer_msg msg;

	ret = lttcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		DBG("Consumer received unexpected message size %zd (expects %zu)",
			ret, sizeof(msg));
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
		return ret;
	}
	if (msg.cmd_type == LTTNG_CONSUMER_STOP) {
		return -ENOENT;
	}

	/* relayd needs RCU read-side lock */
	rcu_read_lock();

	switch (msg.cmd_type) {
	case LTTNG_CONSUMER_ADD_RELAYD_SOCKET:
	{
		ret = consumer_add_relayd_socket(msg.u.relayd_sock.net_index,
				msg.u.relayd_sock.type, ctx, sock, consumer_sockpoll,
				&msg.u.relayd_sock.sock);
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_ADD_CHANNEL:
	{
		struct lttng_consumer_channel *new_channel;
		int fds[1];
		size_t nb_fd = 1;

		DBG("UST Consumer adding channel");

		/* block */
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			rcu_read_unlock();
			return -EINTR;
		}
		ret = lttcomm_recv_fds_unix_sock(sock, fds, nb_fd);
		if (ret != sizeof(fds)) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
			rcu_read_unlock();
			return ret;
		}

		DBG("consumer_add_channel %d", msg.u.channel.channel_key);

		new_channel = consumer_allocate_channel(msg.u.channel.channel_key,
				fds[0], -1,
				msg.u.channel.mmap_len,
				msg.u.channel.max_sb_size,
				msg.u.channel.nb_init_streams);
		if (new_channel == NULL) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
			goto end_nosignal;
		}
		if (ctx->on_recv_channel != NULL) {
			ret = ctx->on_recv_channel(new_channel);
			if (ret == 0) {
				consumer_add_channel(new_channel);
			} else if (ret < 0) {
				goto end_nosignal;
			}
		} else {
			consumer_add_channel(new_channel);
		}
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_ADD_STREAM:
	{
		struct lttng_consumer_stream *new_stream;
		int fds[2], stream_pipe;
		size_t nb_fd = 2;
		struct consumer_relayd_sock_pair *relayd = NULL;
		int alloc_ret = 0;

		DBG("UST Consumer adding stream");

		/* block */
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			rcu_read_unlock();
			return -EINTR;
		}
		ret = lttcomm_recv_fds_unix_sock(sock, fds, nb_fd);
		if (ret != sizeof(fds)) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
			rcu_read_unlock();
			return ret;
		}

		DBG("Consumer command ADD_STREAM chan %d stream %d",
				msg.u.stream.channel_key, msg.u.stream.stream_key);

		assert(msg.u.stream.output == LTTNG_EVENT_MMAP);
		new_stream = consumer_allocate_stream(msg.u.stream.channel_key,
				msg.u.stream.stream_key,
				fds[0], fds[1],
				msg.u.stream.state,
				msg.u.stream.mmap_len,
				msg.u.stream.output,
				msg.u.stream.path_name,
				msg.u.stream.uid,
				msg.u.stream.gid,
				msg.u.stream.net_index,
				msg.u.stream.metadata_flag,
				msg.u.stream.session_id,
				&alloc_ret);
		if (new_stream == NULL) {
			switch (alloc_ret) {
			case -ENOMEM:
			case -EINVAL:
			default:
				lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
				break;
			case -ENOENT:
				/*
				 * We could not find the channel. Can happen if cpu hotplug
				 * happens while tearing down.
				 */
				DBG3("Could not find channel");
				break;
			}
			goto end_nosignal;
		}

		/* The stream is not metadata. Get relayd reference if exists. */
		relayd = consumer_find_relayd(msg.u.stream.net_index);
		if (relayd != NULL) {
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			/* Add stream on the relayd */
			ret = relayd_add_stream(&relayd->control_sock,
					msg.u.stream.name, msg.u.stream.path_name,
					&new_stream->relayd_stream_id);
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
			if (ret < 0) {
				consumer_del_stream(new_stream, NULL);
				goto end_nosignal;
			}
		} else if (msg.u.stream.net_index != -1) {
			ERR("Network sequence index %d unknown. Not adding stream.",
					msg.u.stream.net_index);
			consumer_del_stream(new_stream, NULL);
			goto end_nosignal;
		}

		/* Do actions once stream has been received. */
		if (ctx->on_recv_stream) {
			ret = ctx->on_recv_stream(new_stream);
			if (ret < 0) {
				consumer_del_stream(new_stream, NULL);
				goto end_nosignal;
			}
		}

		/* Get the right pipe where the stream will be sent. */
		if (new_stream->metadata_flag) {
			stream_pipe = ctx->consumer_metadata_pipe[1];
		} else {
			stream_pipe = ctx->consumer_data_pipe[1];
		}

		do {
			ret = write(stream_pipe, &new_stream, sizeof(new_stream));
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			PERROR("Consumer write %s stream to pipe %d",
					new_stream->metadata_flag ? "metadata" : "data",
					stream_pipe);
			consumer_del_stream(new_stream, NULL);
			goto end_nosignal;
		}

		DBG("UST consumer ADD_STREAM %s (%d,%d) with relayd id %" PRIu64,
				msg.u.stream.path_name, fds[0], fds[1],
				new_stream->relayd_stream_id);
		break;
	}
	case LTTNG_CONSUMER_DESTROY_RELAYD:
	{
		uint64_t index = msg.u.destroy_relayd.net_seq_idx;
		struct consumer_relayd_sock_pair *relayd;

		DBG("UST consumer destroying relayd %" PRIu64, index);

		/* Get relayd reference if exists. */
		relayd = consumer_find_relayd(index);
		if (relayd == NULL) {
			ERR("Unable to find relayd %" PRIu64, index);
			goto end_nosignal;
		}

		/*
		 * Each relayd socket pair has a refcount of stream attached to it
		 * which tells if the relayd is still active or not depending on the
		 * refcount value.
		 *
		 * This will set the destroy flag of the relayd object and destroy it
		 * if the refcount reaches zero when called.
		 *
		 * The destroy can happen either here or when a stream fd hangs up.
		 */
		consumer_flag_relayd_for_destroy(relayd);

		goto end_nosignal;
	}
	case LTTNG_CONSUMER_UPDATE_STREAM:
	{
		rcu_read_unlock();
		return -ENOSYS;
	}
	case LTTNG_CONSUMER_DATA_AVAILABLE:
	{
		int32_t ret;
		uint64_t id = msg.u.data_available.session_id;

		DBG("UST consumer data available command for id %" PRIu64, id);

		ret = consumer_data_available(id);

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &ret, sizeof(ret));
		if (ret < 0) {
			PERROR("send data available ret code");
		}
		break;
	}
	default:
		break;
	}

end_nosignal:
	rcu_read_unlock();

	/*
	 * Return 1 to indicate success since the 0 value can be a socket
	 * shutdown during the recv() or send() call.
	 */
	return 1;
}

int lttng_ustconsumer_allocate_channel(struct lttng_consumer_channel *chan)
{
	struct lttng_ust_object_data obj;

	obj.handle = -1;
	obj.shm_fd = chan->shm_fd;
	obj.wait_fd = chan->wait_fd;
	obj.memory_map_size = chan->mmap_len;
	chan->handle = ustctl_map_channel(&obj);
	if (!chan->handle) {
		return -ENOMEM;
	}
	chan->wait_fd_is_copy = 1;
	chan->shm_fd = -1;

	return 0;
}

void lttng_ustconsumer_on_stream_hangup(struct lttng_consumer_stream *stream)
{
	ustctl_flush_buffer(stream->chan->handle, stream->buf, 0);
	stream->hangup_flush_done = 1;
}

void lttng_ustconsumer_del_channel(struct lttng_consumer_channel *chan)
{
	ustctl_unmap_channel(chan->handle);
}

int lttng_ustconsumer_add_stream(struct lttng_consumer_stream *stream)
{
	struct lttng_ust_object_data obj;
	int ret;

	obj.handle = -1;
	obj.shm_fd = stream->shm_fd;
	obj.wait_fd = stream->wait_fd;
	obj.memory_map_size = stream->mmap_len;
	ret = ustctl_add_stream(stream->chan->handle, &obj);
	if (ret) {
		ERR("UST ctl add_stream failed with ret %d", ret);
		goto error;
	}

	stream->buf = ustctl_open_stream_read(stream->chan->handle, stream->cpu);
	if (!stream->buf) {
		ERR("UST ctl open_stream_read failed");
		ret = -EBUSY;
		goto error;
	}

	/* ustctl_open_stream_read has closed the shm fd. */
	stream->wait_fd_is_copy = 1;
	stream->shm_fd = -1;

	stream->mmap_base = ustctl_get_mmap_base(stream->chan->handle, stream->buf);
	if (!stream->mmap_base) {
		ERR("UST ctl get_mmap_base failed");
		ret = -EINVAL;
		goto mmap_error;
	}

	return 0;

mmap_error:
	ustctl_close_stream_read(stream->chan->handle, stream->buf);
error:
	return ret;
}

void lttng_ustconsumer_del_stream(struct lttng_consumer_stream *stream)
{
	ustctl_close_stream_read(stream->chan->handle, stream->buf);
}


int lttng_ustconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	unsigned long len, subbuf_size, padding;
	int err;
	long ret = 0;
	struct lttng_ust_shm_handle *handle;
	struct lttng_ust_lib_ring_buffer *buf;
	char dummy;
	ssize_t readlen;

	DBG("In read_subbuffer (wait_fd: %d, stream key: %d)",
		stream->wait_fd, stream->key);

	/* We can consume the 1 byte written into the wait_fd by UST */
	if (!stream->hangup_flush_done) {
		do {
			readlen = read(stream->wait_fd, &dummy, 1);
		} while (readlen == -1 && errno == EINTR);
		if (readlen == -1) {
			ret = readlen;
			goto end;
		}
	}

	buf = stream->buf;
	handle = stream->chan->handle;
	/* Get the next subbuffer */
	err = ustctl_get_next_subbuf(handle, buf);
	if (err != 0) {
		ret = err;	/* ustctl_get_next_subbuf returns negative, caller expect positive. */
		/*
		 * This is a debug message even for single-threaded consumer,
		 * because poll() have more relaxed criterions than get subbuf,
		 * so get_subbuf may fail for short race windows where poll()
		 * would issue wakeups.
		 */
		DBG("Reserving sub buffer failed (everything is normal, "
				"it is due to concurrency)");
		goto end;
	}
	assert(stream->output == LTTNG_EVENT_MMAP);
	/* Get the full padded subbuffer size */
	err = ustctl_get_padded_subbuf_size(handle, buf, &len);
	assert(err == 0);

	/* Get subbuffer data size (without padding) */
	err = ustctl_get_subbuf_size(handle, buf, &subbuf_size);
	assert(err == 0);

	/* Make sure we don't get a subbuffer size bigger than the padded */
	assert(len >= subbuf_size);

	padding = len - subbuf_size;
	/* write the subbuffer to the tracefile */
	ret = lttng_consumer_on_read_subbuffer_mmap(ctx, stream, subbuf_size, padding);
	/*
	 * The mmap operation should write subbuf_size amount of data when network
	 * streaming or the full padding (len) size when we are _not_ streaming.
	 */
	if ((ret != subbuf_size && stream->net_seq_idx != -1) ||
			(ret != len && stream->net_seq_idx == -1)) {
		/*
		 * Display the error but continue processing to try to release the
		 * subbuffer
		 */
		ERR("Error writing to tracefile "
				"(ret: %zd != len: %lu != subbuf_size: %lu)",
				ret, len, subbuf_size);
	}
	err = ustctl_put_next_subbuf(handle, buf);
	assert(err == 0);
end:
	return ret;
}

int lttng_ustconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	/* Opening the tracefile in write mode */
	if (stream->path_name != NULL && stream->net_seq_idx == -1) {
		ret = run_as_open(stream->path_name,
				O_WRONLY|O_CREAT|O_TRUNC,
				S_IRWXU|S_IRWXG|S_IRWXO,
				stream->uid, stream->gid);
		if (ret < 0) {
			ERR("Opening %s", stream->path_name);
			PERROR("open");
			goto error;
		}
		stream->out_fd = ret;
	}

	ret = lttng_ustconsumer_add_stream(stream);
	if (ret) {
		consumer_del_stream(stream, NULL);
		ret = -1;
		goto error;
	}

	/* we return 0 to let the library handle the FD internally */
	return 0;

error:
	return ret;
}

/*
 * Check if data is still being extracted from the buffers for a specific
 * stream. Consumer data lock MUST be acquired before calling this function.
 *
 * Return 0 if the traced data are still getting read else 1 meaning that the
 * data is available for trace viewer reading.
 */
int lttng_ustconsumer_data_available(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);

	DBG("UST consumer checking data availability");

	/*
	 * Try to lock the stream mutex. On failure, we know that the stream is
	 * being used else where hence there is data still being extracted.
	 */
	ret = pthread_mutex_trylock(&stream->lock);
	if (ret == EBUSY) {
		/* Data not available */
		ret = 0;
		goto end;
	}
	/* The stream is now locked so we can do our ustctl calls */

	ret = ustctl_get_next_subbuf(stream->chan->handle, stream->buf);
	if (ret == 0) {
		/* There is still data so let's put back this subbuffer. */
		ret = ustctl_put_subbuf(stream->chan->handle, stream->buf);
		assert(ret == 0);
		goto end_unlock;
	}

	/* Data is available to be read for this stream. */
	ret = 1;

end_unlock:
	pthread_mutex_unlock(&stream->lock);
end:
	return ret;
}
