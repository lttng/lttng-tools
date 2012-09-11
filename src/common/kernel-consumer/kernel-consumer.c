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
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>

#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/sessiond-comm/relayd.h>
#include <common/compat/fcntl.h>
#include <common/relayd/relayd.h>

#include "kernel-consumer.h"

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;
extern volatile int consumer_quit;

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
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_CMD);
		return ret;
	}
	if (msg.cmd_type == LTTNG_CONSUMER_STOP) {
		return -ENOENT;
	}

	/* relayd needs RCU read-side protection */
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

		DBG("consumer_add_channel %d", msg.u.channel.channel_key);
		new_channel = consumer_allocate_channel(msg.u.channel.channel_key,
				-1, -1,
				msg.u.channel.mmap_len,
				msg.u.channel.max_sb_size);
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
		int fd;
		struct consumer_relayd_sock_pair *relayd = NULL;
		struct lttng_consumer_stream *new_stream;

		/* block */
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			rcu_read_unlock();
			return -EINTR;
		}

		/* Get stream file descriptor from socket */
		ret = lttcomm_recv_fds_unix_sock(sock, &fd, 1);
		if (ret != sizeof(fd)) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
			rcu_read_unlock();
			return ret;
		}

		new_stream = consumer_allocate_stream(msg.u.stream.channel_key,
				msg.u.stream.stream_key,
				fd, fd,
				msg.u.stream.state,
				msg.u.stream.mmap_len,
				msg.u.stream.output,
				msg.u.stream.path_name,
				msg.u.stream.uid,
				msg.u.stream.gid,
				msg.u.stream.net_index,
				msg.u.stream.metadata_flag);
		if (new_stream == NULL) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
			goto end_nosignal;
		}

		/*
		 * The buffer flush is done on the session daemon side for the kernel
		 * so no need for the stream "hangup_flush_done" variable to be
		 * tracked. This is important for a kernel stream since we don't rely
		 * on the flush state of the stream to read data. It's not the case for
		 * user space tracing.
		 */
		new_stream->hangup_flush_done = 0;

		/* The stream is not metadata. Get relayd reference if exists. */
		relayd = consumer_find_relayd(msg.u.stream.net_index);
		if (relayd != NULL) {
			/* Add stream on the relayd */
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			ret = relayd_add_stream(&relayd->control_sock,
					msg.u.stream.name, msg.u.stream.path_name,
					&new_stream->relayd_stream_id);
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
			if (ret < 0) {
				goto end_nosignal;
			}
		} else if (msg.u.stream.net_index != -1) {
			ERR("Network sequence index %d unknown. Not adding stream.",
					msg.u.stream.net_index);
			free(new_stream);
			goto end_nosignal;
		}

		/* Send stream to the metadata thread */
		if (new_stream->metadata_flag) {
			if (ctx->on_recv_stream) {
				ret = ctx->on_recv_stream(new_stream);
				if (ret < 0) {
					goto end_nosignal;
				}
			}

			do {
				ret = write(ctx->consumer_metadata_pipe[1], new_stream,
						sizeof(struct lttng_consumer_stream));
			} while (ret < 0 && errno == EINTR);
			if (ret < 0) {
				PERROR("write metadata pipe");
			}
		} else {
			if (ctx->on_recv_stream) {
				ret = ctx->on_recv_stream(new_stream);
				if (ret < 0) {
					goto end_nosignal;
				}
			}
			consumer_add_stream(new_stream);
		}

		DBG("Kernel consumer_add_stream (%d)", fd);
		break;
	}
	case LTTNG_CONSUMER_UPDATE_STREAM:
	{
		rcu_read_unlock();
		return -ENOSYS;
	}
	case LTTNG_CONSUMER_DESTROY_RELAYD:
	{
		uint64_t index = msg.u.destroy_relayd.net_seq_idx;
		struct consumer_relayd_sock_pair *relayd;

		DBG("Kernel consumer destroying relayd %" PRIu64, index);

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
	default:
		goto end_nosignal;
	}

	/*
	 * Wake-up the other end by writing a null byte in the pipe (non-blocking).
	 * Important note: Because writing into the pipe is non-blocking (and
	 * therefore we allow dropping wakeup data, as long as there is wakeup data
	 * present in the pipe buffer to wake up the other end), the other end
	 * should perform the following sequence for waiting:
	 *
	 * 1) empty the pipe (reads).
	 * 2) perform update operation.
	 * 3) wait on the pipe (poll).
	 */
	do {
		ret = write(ctx->consumer_poll_pipe[1], "", 1);
	} while (ret < 0 && errno == EINTR);
end_nosignal:
	rcu_read_unlock();

	/*
	 * Return 1 to indicate success since the 0 value can be a socket
	 * shutdown during the recv() or send() call.
	 */
	return 1;
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
			if (ret != len) {
				/*
				 * display the error but continue processing to try
				 * to release the subbuffer
				 */
				ERR("Error splicing to tracefile (ret: %zd != len: %lu)",
						ret, len);
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
			if (ret != len) {
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
	if (strlen(stream->path_name) > 0 && stream->net_seq_idx == -1) {
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

