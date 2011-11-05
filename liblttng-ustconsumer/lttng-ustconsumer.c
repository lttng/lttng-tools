/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <lttng-sessiond-comm.h>
#include <lttng/lttng-ustconsumer.h>
#include <lttng/ust-ctl.h>
#include <lttngerr.h>

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;
extern volatile int consumer_quit;

/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written
 */
int lttng_ustconsumer_on_read_subbuffer_mmap(
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
		ret = -errno;
		perror("ustctl_get_mmap_read_offset");
		goto end;
	}
	while (len > 0) {
		ret = write(outfd, stream->mmap_base + mmap_offset, len);
		if (ret >= len) {
			len = 0;
		} else if (ret < 0) {
			ret = -errno;
			perror("Error in file write");
			goto end;
		}
		/* This won't block, but will start writeout asynchronously */
		sync_file_range(outfd, stream->out_fd_offset, ret,
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
int lttng_ustconsumer_on_read_subbuffer_splice(
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
		ret = errno;
		perror("Getting sub-buffer snapshot.");
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
		ret = errno;
		perror("kernctl_snapshot_get_produced");
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
		new_stream = consumer_allocate_stream(msg.u.stream.channel_key,
				msg.u.stream.stream_key,
				fds[0], fds[1],
				msg.u.stream.state,
				msg.u.stream.mmap_len,
				msg.u.stream.output,
				msg.u.stream.path_name);
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
		break;
	}
	default:
		break;
	}
end:
	/* signal the poll thread */
	ret = write(ctx->consumer_poll_pipe[1], "4", 1);
	if (ret < 0) {
		perror("write consumer poll");
	}
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
	/*
	 * The channel fds are passed to ustctl, we only keep a copy.
	 */
	chan->shm_fd_is_copy = 1;
	chan->wait_fd_is_copy = 1;

	return 0;
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
	stream->mmap_base = ustctl_get_mmap_base(stream->chan->handle, stream->buf);
	if (!stream->mmap_base) {
		return -EINVAL;
	}
	/*
	 * The stream fds are passed to ustctl, we only keep a copy.
	 */
	stream->shm_fd_is_copy = 1;
	stream->wait_fd_is_copy = 1;

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
	do {
		readlen = read(stream->wait_fd, &dummy, 1);
	} while (readlen == -1 && errno == -EINTR);
	if (readlen == -1) {
		ret = readlen;
		goto end;
	}

	buf = stream->buf;
	handle = stream->chan->handle;
	/* Get the next subbuffer */
	err = ustctl_get_next_subbuf(handle, buf);
	if (err != 0) {
		ret = errno;
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
	if (err != 0) {
		ret = errno;
		perror("Getting sub-buffer len failed.");
		goto end;
	}
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
	if (err != 0) {
		ret = errno;
		if (errno == EFAULT) {
			perror("Error in unreserving sub buffer\n");
		} else if (errno == EIO) {
			/* Should never happen with newer LTTng versions */
			perror("Reader has been pushed by the writer, last sub-buffer corrupted.");
		}
		goto end;
	}
end:
	return ret;
}

int lttng_ustconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	/* Opening the tracefile in write mode */
	if (stream->path_name != NULL) {
		ret = open(stream->path_name,
				O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);
		if (ret < 0) {
			ERR("Opening %s", stream->path_name);
			perror("open");
			goto error;
		}
		stream->out_fd = ret;
	}

	/* we return 0 to let the library handle the FD internally */
	return 0;

error:
	return ret;
}
