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
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/compat/fcntl.h>

#include "kernel-consumer.h"

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;
extern volatile int consumer_quit;

/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written
 */
ssize_t lttng_kconsumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len)
{
	unsigned long mmap_offset;
	ssize_t ret = 0;
	off_t orig_offset = stream->out_fd_offset;
	int fd = stream->wait_fd;
	int outfd = stream->out_fd;

	/* get the offset inside the fd to mmap */
	ret = kernctl_get_mmap_read_offset(fd, &mmap_offset);
	if (ret != 0) {
		errno = -ret;
		perror("kernctl_get_mmap_read_offset");
		goto end;
	}

	while (len > 0) {
		ret = write(outfd, stream->mmap_base + mmap_offset, len);
		if (ret >= len) {
			len = 0;
		} else if (ret < 0) {
			errno = -ret;
			perror("Error in file write");
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
ssize_t lttng_kconsumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len)
{
	ssize_t ret = 0;
	loff_t offset = 0;
	off_t orig_offset = stream->out_fd_offset;
	int fd = stream->wait_fd;
	int outfd = stream->out_fd;

	while (len > 0) {
		DBG("splice chan to pipe offset %lu (fd : %d)",
				(unsigned long)offset, fd);
		ret = splice(fd, &offset, ctx->consumer_thread_pipe[1], NULL, len,
				SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice chan to pipe ret %zd", ret);
		if (ret < 0) {
			errno = -ret;
			perror("Error in relay splice");
			goto splice_error;
		}

		ret = splice(ctx->consumer_thread_pipe[0], NULL, outfd, NULL, ret,
				SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice pipe to file %zd", ret);
		if (ret < 0) {
			errno = -ret;
			perror("Error in file splice");
			goto splice_error;
		}
		len -= ret;
		/* This won't block, but will start writeout asynchronously */
		lttng_sync_file_range(outfd, stream->out_fd_offset, ret,
				SYNC_FILE_RANGE_WRITE);
		stream->out_fd_offset += ret;
	}
	lttng_consumer_sync_trace_file(stream, orig_offset);

	goto end;

splice_error:
	/* send the appropriate error description to sessiond */
	switch(ret) {
	case EBADF:
		lttng_consumer_send_error(ctx, CONSUMERD_SPLICE_EBADF);
		break;
	case EINVAL:
		lttng_consumer_send_error(ctx, CONSUMERD_SPLICE_EINVAL);
		break;
	case ENOMEM:
		lttng_consumer_send_error(ctx, CONSUMERD_SPLICE_ENOMEM);
		break;
	case ESPIPE:
		lttng_consumer_send_error(ctx, CONSUMERD_SPLICE_ESPIPE);
		break;
	}

end:
	return ret;
}

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_take_snapshot(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream)
{
	int ret = 0;
	int infd = stream->wait_fd;

	ret = kernctl_snapshot(infd);
	if (ret != 0) {
		errno = -ret;
		perror("Getting sub-buffer snapshot.");
	}

	return ret;
}

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_get_produced_snapshot(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream,
		unsigned long *pos)
{
	int ret;
	int infd = stream->wait_fd;

	ret = kernctl_snapshot_get_produced(infd, pos);
	if (ret != 0) {
		errno = -ret;
		perror("kernctl_snapshot_get_produced");
	}

	return ret;
}

int lttng_kconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll)
{
	ssize_t ret;
	struct lttcomm_consumer_msg msg;

	ret = lttcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		lttng_consumer_send_error(ctx, CONSUMERD_ERROR_RECV_CMD);
		return ret;
	}
	if (msg.cmd_type == LTTNG_CONSUMER_STOP) {
		return -ENOENT;
	}

	switch (msg.cmd_type) {
	case LTTNG_CONSUMER_ADD_CHANNEL:
	{
		struct lttng_consumer_channel *new_channel;

		DBG("consumer_add_channel %d", msg.u.channel.channel_key);
		new_channel = consumer_allocate_channel(msg.u.channel.channel_key,
				-1, -1,
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
		int fd;

		/* block */
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			return -EINTR;
		}
		ret = lttcomm_recv_fds_unix_sock(sock, &fd, 1);
		if (ret != sizeof(fd)) {
			lttng_consumer_send_error(ctx, CONSUMERD_ERROR_RECV_FD);
			return ret;
		}

		DBG("consumer_add_stream %s (%d)", msg.u.stream.path_name,
			fd);
		new_stream = consumer_allocate_stream(msg.u.stream.channel_key,
				msg.u.stream.stream_key,
				fd, fd,
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

/*
 * Consume data on a file descriptor and write it on a trace file.
 */
ssize_t lttng_kconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	unsigned long len;
	int err;
	ssize_t ret = 0;
	int infd = stream->wait_fd;

	DBG("In read_subbuffer (infd : %d)", infd);
	/* Get the next subbuffer */
	err = kernctl_get_next_subbuf(infd);
	if (err != 0) {
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

	switch (stream->output) {
		case LTTNG_EVENT_SPLICE:
			/* read the whole subbuffer */
			err = kernctl_get_padded_subbuf_size(infd, &len);
			if (err != 0) {
				errno = -ret;
				perror("Getting sub-buffer len failed.");
				goto end;
			}

			/* splice the subbuffer to the tracefile */
			ret = lttng_consumer_on_read_subbuffer_splice(ctx, stream, len);
			if (ret < 0) {
				/*
				 * display the error but continue processing to try
				 * to release the subbuffer
				 */
				ERR("Error splicing to tracefile");
			}
			break;
		case LTTNG_EVENT_MMAP:
			/* read the used subbuffer size */
			err = kernctl_get_padded_subbuf_size(infd, &len);
			if (err != 0) {
				errno = -ret;
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
			break;
		default:
			ERR("Unknown output method");
			ret = -1;
	}

	err = kernctl_put_next_subbuf(infd);
	if (err != 0) {
		errno = -ret;
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

int lttng_kconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
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
			perror("open");
			goto error;
		}
		stream->out_fd = ret;
	}

	if (stream->output == LTTNG_EVENT_MMAP) {
		/* get the len of the mmap region */
		unsigned long mmap_len;

		ret = kernctl_get_mmap_len(stream->wait_fd, &mmap_len);
		if (ret != 0) {
			errno = -ret;
			perror("kernctl_get_mmap_len");
			goto error_close_fd;
		}
		stream->mmap_len = (size_t) mmap_len;

		stream->mmap_base = mmap(NULL, stream->mmap_len,
				PROT_READ, MAP_PRIVATE, stream->wait_fd, 0);
		if (stream->mmap_base == MAP_FAILED) {
			perror("Error mmaping");
			ret = -1;
			goto error_close_fd;
		}
	}

	/* we return 0 to let the library handle the FD internally */
	return 0;

error_close_fd:
	{
		int err;

		err = close(stream->out_fd);
		assert(!err);
	}
error:
	return ret;
}

