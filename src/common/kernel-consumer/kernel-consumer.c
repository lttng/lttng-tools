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
#include <common/utils.h>

#include "kernel-consumer.h"

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;
extern volatile int consumer_quit;

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_take_snapshot(struct lttng_consumer_stream *stream)
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
int lttng_kconsumer_get_produced_snapshot(struct lttng_consumer_stream *stream,
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
	enum lttng_error_code ret_code = LTTNG_OK;
	struct lttcomm_consumer_msg msg;

	ret = lttcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_CMD);
		return ret;
	}
	if (msg.cmd_type == LTTNG_CONSUMER_STOP) {
		/*
		 * Notify the session daemon that the command is completed.
		 *
		 * On transport layer error, the function call will print an error
		 * message so handling the returned code is a bit useless since we
		 * return an error code anyway.
		 */
		(void) consumer_send_status_msg(sock, ret_code);
		return -ENOENT;
	}

	/* relayd needs RCU read-side protection */
	rcu_read_lock();

	switch (msg.cmd_type) {
	case LTTNG_CONSUMER_ADD_RELAYD_SOCKET:
	{
		/* Session daemon status message are handled in the following call. */
		ret = consumer_add_relayd_socket(msg.u.relayd_sock.net_index,
				msg.u.relayd_sock.type, ctx, sock, consumer_sockpoll,
				&msg.u.relayd_sock.sock, msg.u.relayd_sock.session_id);
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_ADD_CHANNEL:
	{
		struct lttng_consumer_channel *new_channel;

		/* First send a status message before receiving the fds. */
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}

		DBG("consumer_add_channel %" PRIu64, msg.u.channel.channel_key);
		new_channel = consumer_allocate_channel(msg.u.channel.channel_key,
				msg.u.channel.session_id, msg.u.channel.pathname,
				msg.u.channel.name, msg.u.channel.uid, msg.u.channel.gid,
				msg.u.channel.relayd_id, msg.u.channel.output,
				msg.u.channel.tracefile_size,
				msg.u.channel.tracefile_count);
		if (new_channel == NULL) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
			goto end_nosignal;
		}
		new_channel->nb_init_stream_left = msg.u.channel.nb_init_streams;

		/* Translate and save channel type. */
		switch (msg.u.channel.type) {
		case CONSUMER_CHANNEL_TYPE_DATA:
		case CONSUMER_CHANNEL_TYPE_METADATA:
			new_channel->type = msg.u.channel.type;
			break;
		default:
			assert(0);
			goto end_nosignal;
		};

		if (ctx->on_recv_channel != NULL) {
			ret = ctx->on_recv_channel(new_channel);
			if (ret == 0) {
				consumer_add_channel(new_channel, ctx);
			} else if (ret < 0) {
				goto end_nosignal;
			}
		} else {
			consumer_add_channel(new_channel, ctx);
		}
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_ADD_STREAM:
	{
		int fd, stream_pipe;
		struct consumer_relayd_sock_pair *relayd = NULL;
		struct lttng_consumer_stream *new_stream;
		struct lttng_consumer_channel *channel;
		int alloc_ret = 0;

		/*
		 * Get stream's channel reference. Needed when adding the stream to the
		 * global hash table.
		 */
		channel = consumer_find_channel(msg.u.stream.channel_key);
		if (!channel) {
			/*
			 * We could not find the channel. Can happen if cpu hotplug
			 * happens while tearing down.
			 */
			ERR("Unable to find channel key %" PRIu64, msg.u.stream.channel_key);
			ret_code = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
		}

		/* First send a status message before receiving the fds. */
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0 || ret_code != LTTNG_OK) {
			/*
			 * Somehow, the session daemon is not responding anymore or the
			 * channel was not found.
			 */
			goto end_nosignal;
		}

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

		/*
		 * Send status code to session daemon only if the recv works. If the
		 * above recv() failed, the session daemon is notified through the
		 * error socket and the teardown is eventually done.
		 */
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}

		new_stream = consumer_allocate_stream(channel->key,
				fd,
				LTTNG_CONSUMER_ACTIVE_STREAM,
				channel->name,
				channel->uid,
				channel->gid,
				channel->relayd_id,
				channel->session_id,
				msg.u.stream.cpu,
				&alloc_ret,
				channel->type);
		if (new_stream == NULL) {
			switch (alloc_ret) {
			case -ENOMEM:
			case -EINVAL:
			default:
				lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
				break;
			}
			goto end_nosignal;
		}
		new_stream->chan = channel;
		new_stream->wait_fd = fd;

		/*
		 * The buffer flush is done on the session daemon side for the kernel
		 * so no need for the stream "hangup_flush_done" variable to be
		 * tracked. This is important for a kernel stream since we don't rely
		 * on the flush state of the stream to read data. It's not the case for
		 * user space tracing.
		 */
		new_stream->hangup_flush_done = 0;

		/* The stream is not metadata. Get relayd reference if exists. */
		relayd = consumer_find_relayd(new_stream->net_seq_idx);
		if (relayd != NULL) {
			/* Add stream on the relayd */
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			ret = relayd_add_stream(&relayd->control_sock,
					new_stream->name, new_stream->chan->pathname,
					&new_stream->relayd_stream_id);
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
			if (ret < 0) {
				consumer_del_stream(new_stream, NULL);
				goto end_nosignal;
			}
		} else if (new_stream->net_seq_idx != (uint64_t) -1ULL) {
			ERR("Network sequence index %" PRIu64 " unknown. Not adding stream.",
					new_stream->net_seq_idx);
			consumer_del_stream(new_stream, NULL);
			goto end_nosignal;
		}

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

		DBG("Kernel consumer ADD_STREAM %s (fd: %d) with relayd id %" PRIu64,
				new_stream->name, fd, new_stream->relayd_stream_id);
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
			DBG("Unable to find relayd %" PRIu64, index);
			ret_code = LTTNG_ERR_NO_CONSUMER;
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
		if (relayd) {
			consumer_flag_relayd_for_destroy(relayd);
		}

		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}

		goto end_nosignal;
	}
	case LTTNG_CONSUMER_DATA_PENDING:
	{
		int32_t ret;
		uint64_t id = msg.u.data_pending.session_id;

		DBG("Kernel consumer data pending command for id %" PRIu64, id);

		ret = consumer_data_pending(id);

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &ret, sizeof(ret));
		if (ret < 0) {
			PERROR("send data pending ret code");
		}

		/*
		 * No need to send back a status message since the data pending
		 * returned value is the response.
		 */
		break;
	}
	default:
		goto end_nosignal;
	}

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
	unsigned long len, subbuf_size, padding;
	int err;
	ssize_t ret = 0;
	int infd = stream->wait_fd;

	DBG("In read_subbuffer (infd : %d)", infd);
	/* Get the next subbuffer */
	err = kernctl_get_next_subbuf(infd);
	if (err != 0) {
		ret = err;
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

	/* Get the full subbuffer size including padding */
	err = kernctl_get_padded_subbuf_size(infd, &len);
	if (err != 0) {
		errno = -err;
		perror("Getting sub-buffer len failed.");
		ret = err;
		goto end;
	}

	switch (stream->chan->output) {
	case LTTNG_EVENT_SPLICE:

		/*
		 * XXX: The lttng-modules splice "actor" does not handle copying
		 * partial pages hence only using the subbuffer size without the
		 * padding makes the splice fail.
		 */
		subbuf_size = len;
		padding = 0;

		/* splice the subbuffer to the tracefile */
		ret = lttng_consumer_on_read_subbuffer_splice(ctx, stream, subbuf_size,
				padding);
		/*
		 * XXX: Splice does not support network streaming so the return value
		 * is simply checked against subbuf_size and not like the mmap() op.
		 */
		if (ret != subbuf_size) {
			/*
			 * display the error but continue processing to try
			 * to release the subbuffer
			 */
			ERR("Error splicing to tracefile (ret: %zd != len: %lu)",
					ret, subbuf_size);
		}
		break;
	case LTTNG_EVENT_MMAP:
		/* Get subbuffer size without padding */
		err = kernctl_get_subbuf_size(infd, &subbuf_size);
		if (err != 0) {
			errno = -err;
			perror("Getting sub-buffer len failed.");
			ret = err;
			goto end;
		}

		/* Make sure the tracer is not gone mad on us! */
		assert(len >= subbuf_size);

		padding = len - subbuf_size;

		/* write the subbuffer to the tracefile */
		ret = lttng_consumer_on_read_subbuffer_mmap(ctx, stream, subbuf_size,
				padding);
		/*
		 * The mmap operation should write subbuf_size amount of data when
		 * network streaming or the full padding (len) size when we are _not_
		 * streaming.
		 */
		if ((ret != subbuf_size && stream->net_seq_idx != (uint64_t) -1ULL) ||
				(ret != len && stream->net_seq_idx == (uint64_t) -1ULL)) {
			/*
			 * Display the error but continue processing to try to release the
			 * subbuffer
			 */
			ERR("Error writing to tracefile "
					"(ret: %zd != len: %lu != subbuf_size: %lu)",
					ret, len, subbuf_size);
		}
		break;
	default:
		ERR("Unknown output method");
		ret = -1;
	}

	err = kernctl_put_next_subbuf(infd);
	if (err != 0) {
		errno = -err;
		if (errno == EFAULT) {
			perror("Error in unreserving sub buffer\n");
		} else if (errno == EIO) {
			/* Should never happen with newer LTTng versions */
			perror("Reader has been pushed by the writer, last sub-buffer corrupted.");
		}

		ret = -err;
		goto end;
	}

end:
	return ret;
}

int lttng_kconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);

	/* Don't create anything if this is set for streaming. */
	if (stream->net_seq_idx == (uint64_t) -1ULL) {
		ret = utils_create_stream_file(stream->chan->pathname, stream->name,
				stream->chan->tracefile_size, stream->tracefile_count_current,
				stream->uid, stream->gid);
		if (ret < 0) {
			goto error;
		}
		stream->out_fd = ret;
		stream->tracefile_size_current = 0;
	}

	if (stream->output == LTTNG_EVENT_MMAP) {
		/* get the len of the mmap region */
		unsigned long mmap_len;

		ret = kernctl_get_mmap_len(stream->wait_fd, &mmap_len);
		if (ret != 0) {
			errno = -ret;
			PERROR("kernctl_get_mmap_len");
			goto error_close_fd;
		}
		stream->mmap_len = (size_t) mmap_len;

		stream->mmap_base = mmap(NULL, stream->mmap_len, PROT_READ,
				MAP_PRIVATE, stream->wait_fd, 0);
		if (stream->mmap_base == MAP_FAILED) {
			PERROR("Error mmaping");
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

/*
 * Check if data is still being extracted from the buffers for a specific
 * stream. Consumer data lock MUST be acquired before calling this function
 * and the stream lock.
 *
 * Return 1 if the traced data are still getting read else 0 meaning that the
 * data is available for trace viewer reading.
 */
int lttng_kconsumer_data_pending(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);

	ret = kernctl_get_next_subbuf(stream->wait_fd);
	if (ret == 0) {
		/* There is still data so let's put back this subbuffer. */
		ret = kernctl_put_subbuf(stream->wait_fd);
		assert(ret == 0);
		ret = 1;   /* Data is pending */
		goto end;
	}

	/* Data is NOT pending and ready to be read. */
	ret = 0;

end:
	return ret;
}
