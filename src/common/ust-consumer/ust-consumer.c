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
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <lttng/ust-ctl.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/compat/fcntl.h>

#include "ust-consumer.h"

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;
extern volatile int consumer_quit;

/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written, else negative value on error.
 */
ssize_t lttng_ustconsumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len)
{
	unsigned long mmap_offset;
	long ret = 0;
	off_t orig_offset = stream->out_fd_offset;
	int outfd = stream->out_fd;

	/* get the offset inside the fd to mmap */
	ret = ustctl_get_mmap_read_offset(stream->chan->handle,
		stream->buf, &mmap_offset);
	if (ret != 0) {
		errno = -ret;
		PERROR("ustctl_get_mmap_read_offset");
		goto end;
	}
	while (len > 0) {
		ret = write(outfd, stream->mmap_base + mmap_offset, len);
		if (ret >= len) {
			len = 0;
		} else if (ret < 0) {
			errno = -ret;
			PERROR("Error in file write");
			goto end;
		}
		/* This won't block, but will start writeout asynchronously */
		lttng_sync_file_range(outfd, stream->out_fd_offset, ret,
				SYNC_FILE_RANGE_WRITE);
		stream->out_fd_offset += ret;
	}

	lttng_consumer_sync_trace_file(stream, orig_offset);

	goto end;

end:
	return ret;
}

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * Returns the number of bytes spliced.
 */
ssize_t lttng_ustconsumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len)
{
	return -ENOSYS;
}

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

int lttng_ustconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll)
{
	ssize_t ret;
	struct lttcomm_consumer_msg msg;

	ret = lttcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		lttng_consumer_send_error(ctx, CONSUMERD_ERROR_RECV_FD);
		return ret;
	}
	if (msg.cmd_type == LTTNG_CONSUMER_STOP) {
		return -ENOENT;
	}

	switch (msg.cmd_type) {
	case LTTNG_CONSUMER_ADD_CHANNEL:
	{
		struct lttng_consumer_channel *new_channel;
		int fds[1];
		size_t nb_fd = 1;

		/* block */
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			return -EINTR;
		}
		ret = lttcomm_recv_fds_unix_sock(sock, fds, nb_fd);
		if (ret != sizeof(fds)) {
			lttng_consumer_send_error(ctx, CONSUMERD_ERROR_RECV_FD);
			return ret;
		}

		DBG("consumer_add_channel %d", msg.u.channel.channel_key);

		new_channel = consumer_allocate_channel(msg.u.channel.channel_key,
				fds[0], -1,
				msg.u.channel.mmap_len,
				msg.u.channel.max_sb_size);
		if (new_channel == NULL) {
			lttng_consumer_send_error(ctx, CONSUMERD_OUTFD_ERROR);
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
		int fds[2];
		size_t nb_fd = 2;

		/* block */
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			return -EINTR;
		}
		ret = lttcomm_recv_fds_unix_sock(sock, fds, nb_fd);
		if (ret != sizeof(fds)) {
			lttng_consumer_send_error(ctx, CONSUMERD_ERROR_RECV_FD);
			return ret;
		}

		DBG("consumer_add_stream %s (%d,%d)", msg.u.stream.path_name,
			fds[0], fds[1]);
		assert(msg.u.stream.output == LTTNG_EVENT_MMAP);
		new_stream = consumer_allocate_stream(msg.u.channel.channel_key,
				msg.u.stream.stream_key,
				fds[0], fds[1],
				msg.u.stream.state,
				msg.u.stream.mmap_len,
				msg.u.stream.output,
				msg.u.stream.path_name,
				msg.u.stream.uid,
				msg.u.stream.gid);
		if (new_stream == NULL) {
			lttng_consumer_send_error(ctx, CONSUMERD_OUTFD_ERROR);
			goto end;
		}
		if (ctx->on_recv_stream != NULL) {
			ret = ctx->on_recv_stream(new_stream);
			if (ret == 0) {
				consumer_add_stream(new_stream);
			} else if (ret < 0) {
				goto end;
			}
		} else {
			consumer_add_stream(new_stream);
		}
		break;
	}
	case LTTNG_CONSUMER_UPDATE_STREAM:
	{
		return -ENOSYS;
#if 0
		if (ctx->on_update_stream != NULL) {
			ret = ctx->on_update_stream(msg.u.stream.stream_key, msg.u.stream.state);
			if (ret == 0) {
				consumer_change_stream_state(msg.u.stream.stream_key, msg.u.stream.state);
			} else if (ret < 0) {
				goto end;
			}
		} else {
			consumer_change_stream_state(msg.u.stream.stream_key,
				msg.u.stream.state);
		}
#endif
		break;
	}
	default:
		break;
	}
end:
	/*
	 * Wake-up the other end by writing a null byte in the pipe
	 * (non-blocking). Important note: Because writing into the
	 * pipe is non-blocking (and therefore we allow dropping wakeup
	 * data, as long as there is wakeup data present in the pipe
	 * buffer to wake up the other end), the other end should
	 * perform the following sequence for waiting:
	 * 1) empty the pipe (reads).
	 * 2) perform update operation.
	 * 3) wait on the pipe (poll).
	 */
	do {
		ret = write(ctx->consumer_poll_pipe[1], "", 1);
	} while (ret == -1UL && errno == EINTR);
end_nosignal:
	return 0;
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

int lttng_ustconsumer_allocate_stream(struct lttng_consumer_stream *stream)
{
	struct lttng_ust_object_data obj;
	int ret;

	obj.handle = -1;
	obj.shm_fd = stream->shm_fd;
	obj.wait_fd = stream->wait_fd;
	obj.memory_map_size = stream->mmap_len;
	ret = ustctl_add_stream(stream->chan->handle, &obj);
	if (ret)
		return ret;
	stream->buf = ustctl_open_stream_read(stream->chan->handle, stream->cpu);
	if (!stream->buf)
		return -EBUSY;
	/* ustctl_open_stream_read has closed the shm fd. */
	stream->wait_fd_is_copy = 1;
	stream->shm_fd = -1;

	stream->mmap_base = ustctl_get_mmap_base(stream->chan->handle, stream->buf);
	if (!stream->mmap_base) {
		return -EINVAL;
	}

	return 0;
}

void lttng_ustconsumer_del_stream(struct lttng_consumer_stream *stream)
{
	ustctl_close_stream_read(stream->chan->handle, stream->buf);
}


int lttng_ustconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	unsigned long len;
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
		ret = -ret;	/* ustctl_get_next_subbuf returns negative, caller expect positive. */
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
	/* read the used subbuffer size */
	err = ustctl_get_padded_subbuf_size(handle, buf, &len);
	assert(err == 0);
	/* write the subbuffer to the tracefile */
	ret = lttng_consumer_on_read_subbuffer_mmap(ctx, stream, len);
	if (ret < 0) {
		/*
		 * display the error but continue processing to try
		 * to release the subbuffer
		 */
		ERR("Error writing to tracefile");
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
	if (stream->path_name != NULL) {
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

	/* we return 0 to let the library handle the FD internally */
	return 0;

error:
	return ret;
}
