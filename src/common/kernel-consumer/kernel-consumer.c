/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#define _LGPL_SOURCE
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

#include <bin/lttng-consumerd/health-consumerd.h>
#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/sessiond-comm/relayd.h>
#include <common/compat/fcntl.h>
#include <common/compat/endian.h>
#include <common/pipe.h>
#include <common/relayd/relayd.h>
#include <common/utils.h>
#include <common/consumer/consumer-stream.h>
#include <common/index/index.h>
#include <common/consumer/consumer-timer.h>

#include "kernel-consumer.h"

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;

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
		PERROR("Getting sub-buffer snapshot.");
	}

	return ret;
}

/*
 * Sample consumed and produced positions for a specific fd.
 *
 * Returns 0 on success, < 0 on error.
 */
int lttng_kconsumer_sample_snapshot_positions(
		struct lttng_consumer_stream *stream)
{
	assert(stream);

	return kernctl_snapshot_sample_positions(stream->wait_fd);
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
		PERROR("kernctl_snapshot_get_produced");
	}

	return ret;
}

/*
 * Get the consumerd position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_get_consumed_snapshot(struct lttng_consumer_stream *stream,
		unsigned long *pos)
{
	int ret;
	int infd = stream->wait_fd;

	ret = kernctl_snapshot_get_consumed(infd, pos);
	if (ret != 0) {
		PERROR("kernctl_snapshot_get_consumed");
	}

	return ret;
}

/*
 * Take a snapshot of all the stream of a channel
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_snapshot_channel(uint64_t key, char *path,
		uint64_t relayd_id, uint64_t nb_packets_per_stream,
		struct lttng_consumer_local_data *ctx)
{
	int ret;
	struct lttng_consumer_channel *channel;
	struct lttng_consumer_stream *stream;

	DBG("Kernel consumer snapshot channel %" PRIu64, key);

	rcu_read_lock();

	channel = consumer_find_channel(key);
	if (!channel) {
		ERR("No channel found for key %" PRIu64, key);
		ret = -1;
		goto end;
	}

	/* Splice is not supported yet for channel snapshot. */
	if (channel->output != CONSUMER_CHANNEL_MMAP) {
		ERR("Unsupported output %d", channel->output);
		ret = -1;
		goto end;
	}

	cds_list_for_each_entry(stream, &channel->streams.head, send_node) {
		unsigned long consumed_pos, produced_pos;

		health_code_update();

		/*
		 * Lock stream because we are about to change its state.
		 */
		pthread_mutex_lock(&stream->lock);

		/*
		 * Assign the received relayd ID so we can use it for streaming. The streams
		 * are not visible to anyone so this is OK to change it.
		 */
		stream->net_seq_idx = relayd_id;
		channel->relayd_id = relayd_id;
		if (relayd_id != (uint64_t) -1ULL) {
			ret = consumer_send_relayd_stream(stream, path);
			if (ret < 0) {
				ERR("sending stream to relayd");
				goto end_unlock;
			}
		} else {
			ret = utils_create_stream_file(path, stream->name,
					stream->chan->tracefile_size,
					stream->tracefile_count_current,
					stream->uid, stream->gid, NULL);
			if (ret < 0) {
				ERR("utils_create_stream_file");
				goto end_unlock;
			}

			stream->out_fd = ret;
			stream->tracefile_size_current = 0;

			DBG("Kernel consumer snapshot stream %s/%s (%" PRIu64 ")",
					path, stream->name, stream->key);
		}

		ret = kernctl_buffer_flush_empty(stream->wait_fd);
		if (ret < 0) {
			/*
			 * Doing a buffer flush which does not take into
			 * account empty packets. This is not perfect
			 * for stream intersection, but required as a
			 * fall-back when "flush_empty" is not
			 * implemented by lttng-modules.
			 */
			ret = kernctl_buffer_flush(stream->wait_fd);
			if (ret < 0) {
				ERR("Failed to flush kernel stream");
				goto end_unlock;
			}
			goto end_unlock;
		}

		ret = lttng_kconsumer_take_snapshot(stream);
		if (ret < 0) {
			ERR("Taking kernel snapshot");
			goto end_unlock;
		}

		ret = lttng_kconsumer_get_produced_snapshot(stream, &produced_pos);
		if (ret < 0) {
			ERR("Produced kernel snapshot position");
			goto end_unlock;
		}

		ret = lttng_kconsumer_get_consumed_snapshot(stream, &consumed_pos);
		if (ret < 0) {
			ERR("Consumerd kernel snapshot position");
			goto end_unlock;
		}

		if (stream->max_sb_size == 0) {
			ret = kernctl_get_max_subbuf_size(stream->wait_fd,
					&stream->max_sb_size);
			if (ret < 0) {
				ERR("Getting kernel max_sb_size");
				goto end_unlock;
			}
		}

		consumed_pos = consumer_get_consume_start_pos(consumed_pos,
				produced_pos, nb_packets_per_stream,
				stream->max_sb_size);

		while (consumed_pos < produced_pos) {
			ssize_t read_len;
			unsigned long len, padded_len;

			health_code_update();

			DBG("Kernel consumer taking snapshot at pos %lu", consumed_pos);

			ret = kernctl_get_subbuf(stream->wait_fd, &consumed_pos);
			if (ret < 0) {
				if (ret != -EAGAIN) {
					PERROR("kernctl_get_subbuf snapshot");
					goto end_unlock;
				}
				DBG("Kernel consumer get subbuf failed. Skipping it.");
				consumed_pos += stream->max_sb_size;
				stream->chan->lost_packets++;
				continue;
			}

			ret = kernctl_get_subbuf_size(stream->wait_fd, &len);
			if (ret < 0) {
				ERR("Snapshot kernctl_get_subbuf_size");
				goto error_put_subbuf;
			}

			ret = kernctl_get_padded_subbuf_size(stream->wait_fd, &padded_len);
			if (ret < 0) {
				ERR("Snapshot kernctl_get_padded_subbuf_size");
				goto error_put_subbuf;
			}

			read_len = lttng_consumer_on_read_subbuffer_mmap(ctx, stream, len,
					padded_len - len, NULL);
			/*
			 * We write the padded len in local tracefiles but the data len
			 * when using a relay. Display the error but continue processing
			 * to try to release the subbuffer.
			 */
			if (relayd_id != (uint64_t) -1ULL) {
				if (read_len != len) {
					ERR("Error sending to the relay (ret: %zd != len: %lu)",
							read_len, len);
				}
			} else {
				if (read_len != padded_len) {
					ERR("Error writing to tracefile (ret: %zd != len: %lu)",
							read_len, padded_len);
				}
			}

			ret = kernctl_put_subbuf(stream->wait_fd);
			if (ret < 0) {
				ERR("Snapshot kernctl_put_subbuf");
				goto end_unlock;
			}
			consumed_pos += stream->max_sb_size;
		}

		if (relayd_id == (uint64_t) -1ULL) {
			if (stream->out_fd >= 0) {
				ret = close(stream->out_fd);
				if (ret < 0) {
					PERROR("Kernel consumer snapshot close out_fd");
					goto end_unlock;
				}
				stream->out_fd = -1;
			}
		} else {
			close_relayd_stream(stream);
			stream->net_seq_idx = (uint64_t) -1ULL;
		}
		pthread_mutex_unlock(&stream->lock);
	}

	/* All good! */
	ret = 0;
	goto end;

error_put_subbuf:
	ret = kernctl_put_subbuf(stream->wait_fd);
	if (ret < 0) {
		ERR("Snapshot kernctl_put_subbuf error path");
	}
end_unlock:
	pthread_mutex_unlock(&stream->lock);
end:
	rcu_read_unlock();
	return ret;
}

/*
 * Read the whole metadata available for a snapshot.
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_snapshot_metadata(uint64_t key, char *path,
		uint64_t relayd_id, struct lttng_consumer_local_data *ctx)
{
	int ret, use_relayd = 0;
	ssize_t ret_read;
	struct lttng_consumer_channel *metadata_channel;
	struct lttng_consumer_stream *metadata_stream;

	assert(ctx);

	DBG("Kernel consumer snapshot metadata with key %" PRIu64 " at path %s",
			key, path);

	rcu_read_lock();

	metadata_channel = consumer_find_channel(key);
	if (!metadata_channel) {
		ERR("Kernel snapshot metadata not found for key %" PRIu64, key);
		ret = -1;
		goto error;
	}

	metadata_stream = metadata_channel->metadata_stream;
	assert(metadata_stream);

	/* Flag once that we have a valid relayd for the stream. */
	if (relayd_id != (uint64_t) -1ULL) {
		use_relayd = 1;
	}

	if (use_relayd) {
		ret = consumer_send_relayd_stream(metadata_stream, path);
		if (ret < 0) {
			goto error;
		}
	} else {
		ret = utils_create_stream_file(path, metadata_stream->name,
				metadata_stream->chan->tracefile_size,
				metadata_stream->tracefile_count_current,
				metadata_stream->uid, metadata_stream->gid, NULL);
		if (ret < 0) {
			goto error;
		}
		metadata_stream->out_fd = ret;
	}

	do {
		health_code_update();

		ret_read = lttng_kconsumer_read_subbuffer(metadata_stream, ctx);
		if (ret_read < 0) {
			if (ret_read != -EAGAIN) {
				ERR("Kernel snapshot reading metadata subbuffer (ret: %zd)",
						ret_read);
				goto error;
			}
			/* ret_read is negative at this point so we will exit the loop. */
			continue;
		}
	} while (ret_read >= 0);

	if (use_relayd) {
		close_relayd_stream(metadata_stream);
		metadata_stream->net_seq_idx = (uint64_t) -1ULL;
	} else {
		if (metadata_stream->out_fd >= 0) {
			ret = close(metadata_stream->out_fd);
			if (ret < 0) {
				PERROR("Kernel consumer snapshot metadata close out_fd");
				/*
				 * Don't go on error here since the snapshot was successful at this
				 * point but somehow the close failed.
				 */
			}
			metadata_stream->out_fd = -1;
		}
	}

	ret = 0;

	cds_list_del(&metadata_stream->send_node);
	consumer_stream_destroy(metadata_stream, NULL);
	metadata_channel->metadata_stream = NULL;
error:
	rcu_read_unlock();
	return ret;
}

/*
 * Receive command from session daemon and process it.
 *
 * Return 1 on success else a negative value or 0.
 */
int lttng_kconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll)
{
	ssize_t ret;
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct lttcomm_consumer_msg msg;

	health_code_update();

	ret = lttcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		if (ret > 0) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_CMD);
			ret = -1;
		}
		return ret;
	}

	health_code_update();

	/* Deprecated command */
	assert(msg.cmd_type != LTTNG_CONSUMER_STOP);

	health_code_update();

	/* relayd needs RCU read-side protection */
	rcu_read_lock();

	switch (msg.cmd_type) {
	case LTTNG_CONSUMER_ADD_RELAYD_SOCKET:
	{
		/* Session daemon status message are handled in the following call. */
		consumer_add_relayd_socket(msg.u.relayd_sock.net_index,
				msg.u.relayd_sock.type, ctx, sock, consumer_sockpoll,
				&msg.u.relayd_sock.sock, msg.u.relayd_sock.session_id,
				msg.u.relayd_sock.relayd_session_id);
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_ADD_CHANNEL:
	{
		struct lttng_consumer_channel *new_channel;
		int ret_recv;

		health_code_update();

		/* First send a status message before receiving the fds. */
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_fatal;
		}

		health_code_update();

		DBG("consumer_add_channel %" PRIu64, msg.u.channel.channel_key);
		new_channel = consumer_allocate_channel(msg.u.channel.channel_key,
				msg.u.channel.session_id, msg.u.channel.pathname,
				msg.u.channel.name, msg.u.channel.uid, msg.u.channel.gid,
				msg.u.channel.relayd_id, msg.u.channel.output,
				msg.u.channel.tracefile_size,
				msg.u.channel.tracefile_count, 0,
				msg.u.channel.monitor,
				msg.u.channel.live_timer_interval,
				NULL, NULL);
		if (new_channel == NULL) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
			goto end_nosignal;
		}
		new_channel->nb_init_stream_left = msg.u.channel.nb_init_streams;
		switch (msg.u.channel.output) {
		case LTTNG_EVENT_SPLICE:
			new_channel->output = CONSUMER_CHANNEL_SPLICE;
			break;
		case LTTNG_EVENT_MMAP:
			new_channel->output = CONSUMER_CHANNEL_MMAP;
			break;
		default:
			ERR("Channel output unknown %d", msg.u.channel.output);
			goto end_nosignal;
		}

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

		health_code_update();

		if (ctx->on_recv_channel != NULL) {
			ret_recv = ctx->on_recv_channel(new_channel);
			if (ret_recv == 0) {
				ret = consumer_add_channel(new_channel, ctx);
			} else if (ret_recv < 0) {
				goto end_nosignal;
			}
		} else {
			ret = consumer_add_channel(new_channel, ctx);
		}
		if (msg.u.channel.type == CONSUMER_CHANNEL_TYPE_DATA && !ret) {
			int monitor_start_ret;

			DBG("Consumer starting monitor timer");
			consumer_timer_live_start(new_channel,
					msg.u.channel.live_timer_interval);
			monitor_start_ret = consumer_timer_monitor_start(
					new_channel,
					msg.u.channel.monitor_timer_interval);
			if (monitor_start_ret < 0) {
				ERR("Starting channel monitoring timer failed");
				goto end_nosignal;
			}

		}

		health_code_update();

		/* If we received an error in add_channel, we need to report it. */
		if (ret < 0) {
			ret = consumer_send_status_msg(sock, ret);
			if (ret < 0) {
				goto error_fatal;
			}
			goto end_nosignal;
		}

		goto end_nosignal;
	}
	case LTTNG_CONSUMER_ADD_STREAM:
	{
		int fd;
		struct lttng_pipe *stream_pipe;
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
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		}

		health_code_update();

		/* First send a status message before receiving the fds. */
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_fatal;
		}

		health_code_update();

		if (ret_code != LTTCOMM_CONSUMERD_SUCCESS) {
			/* Channel was not found. */
			goto end_nosignal;
		}

		/* Blocking call */
		health_poll_entry();
		ret = lttng_consumer_poll_socket(consumer_sockpoll);
		health_poll_exit();
		if (ret) {
			goto error_fatal;
		}

		health_code_update();

		/* Get stream file descriptor from socket */
		ret = lttcomm_recv_fds_unix_sock(sock, &fd, 1);
		if (ret != sizeof(fd)) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
			rcu_read_unlock();
			return ret;
		}

		health_code_update();

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

		health_code_update();

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
				channel->type,
				channel->monitor);
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
		switch (channel->output) {
		case CONSUMER_CHANNEL_SPLICE:
			new_stream->output = LTTNG_EVENT_SPLICE;
			ret = utils_create_pipe(new_stream->splice_pipe);
			if (ret < 0) {
				goto end_nosignal;
			}
			break;
		case CONSUMER_CHANNEL_MMAP:
			new_stream->output = LTTNG_EVENT_MMAP;
			break;
		default:
			ERR("Stream output unknown %d", channel->output);
			goto end_nosignal;
		}

		/*
		 * We've just assigned the channel to the stream so increment the
		 * refcount right now. We don't need to increment the refcount for
		 * streams in no monitor because we handle manually the cleanup of
		 * those. It is very important to make sure there is NO prior
		 * consumer_del_stream() calls or else the refcount will be unbalanced.
		 */
		if (channel->monitor) {
			uatomic_inc(&new_stream->chan->refcount);
		}

		/*
		 * The buffer flush is done on the session daemon side for the kernel
		 * so no need for the stream "hangup_flush_done" variable to be
		 * tracked. This is important for a kernel stream since we don't rely
		 * on the flush state of the stream to read data. It's not the case for
		 * user space tracing.
		 */
		new_stream->hangup_flush_done = 0;

		health_code_update();

		if (ctx->on_recv_stream) {
			ret = ctx->on_recv_stream(new_stream);
			if (ret < 0) {
				consumer_stream_free(new_stream);
				goto end_nosignal;
			}
		}

		health_code_update();

		if (new_stream->metadata_flag) {
			channel->metadata_stream = new_stream;
		}

		/* Do not monitor this stream. */
		if (!channel->monitor) {
			DBG("Kernel consumer add stream %s in no monitor mode with "
					"relayd id %" PRIu64, new_stream->name,
					new_stream->net_seq_idx);
			cds_list_add(&new_stream->send_node, &channel->streams.head);
			break;
		}

		/* Send stream to relayd if the stream has an ID. */
		if (new_stream->net_seq_idx != (uint64_t) -1ULL) {
			ret = consumer_send_relayd_stream(new_stream,
					new_stream->chan->pathname);
			if (ret < 0) {
				consumer_stream_free(new_stream);
				goto end_nosignal;
			}

			/*
			 * If adding an extra stream to an already
			 * existing channel (e.g. cpu hotplug), we need
			 * to send the "streams_sent" command to relayd.
			 */
			if (channel->streams_sent_to_relayd) {
				ret = consumer_send_relayd_streams_sent(
						new_stream->net_seq_idx);
				if (ret < 0) {
					goto end_nosignal;
				}
			}
		}

		/* Get the right pipe where the stream will be sent. */
		if (new_stream->metadata_flag) {
			consumer_add_metadata_stream(new_stream);
			stream_pipe = ctx->consumer_metadata_pipe;
		} else {
			consumer_add_data_stream(new_stream);
			stream_pipe = ctx->consumer_data_pipe;
		}

		/* Visible to other threads */
		new_stream->globally_visible = 1;

		health_code_update();

		ret = lttng_pipe_write(stream_pipe, &new_stream, sizeof(new_stream));
		if (ret < 0) {
			ERR("Consumer write %s stream to pipe %d",
					new_stream->metadata_flag ? "metadata" : "data",
					lttng_pipe_get_writefd(stream_pipe));
			if (new_stream->metadata_flag) {
				consumer_del_stream_for_metadata(new_stream);
			} else {
				consumer_del_stream_for_data(new_stream);
			}
			goto end_nosignal;
		}

		DBG("Kernel consumer ADD_STREAM %s (fd: %d) with relayd id %" PRIu64,
				new_stream->name, fd, new_stream->relayd_stream_id);
		break;
	}
	case LTTNG_CONSUMER_STREAMS_SENT:
	{
		struct lttng_consumer_channel *channel;

		/*
		 * Get stream's channel reference. Needed when adding the stream to the
		 * global hash table.
		 */
		channel = consumer_find_channel(msg.u.sent_streams.channel_key);
		if (!channel) {
			/*
			 * We could not find the channel. Can happen if cpu hotplug
			 * happens while tearing down.
			 */
			ERR("Unable to find channel key %" PRIu64,
					msg.u.sent_streams.channel_key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		}

		health_code_update();

		/*
		 * Send status code to session daemon.
		 */
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0 || ret_code != LTTCOMM_CONSUMERD_SUCCESS) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}

		health_code_update();

		/*
		 * We should not send this message if we don't monitor the
		 * streams in this channel.
		 */
		if (!channel->monitor) {
			break;
		}

		health_code_update();
		/* Send stream to relayd if the stream has an ID. */
		if (msg.u.sent_streams.net_seq_idx != (uint64_t) -1ULL) {
			ret = consumer_send_relayd_streams_sent(
					msg.u.sent_streams.net_seq_idx);
			if (ret < 0) {
				goto end_nosignal;
			}
			channel->streams_sent_to_relayd = true;
		}
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
			ret_code = LTTCOMM_CONSUMERD_RELAYD_FAIL;
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

		health_code_update();

		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_fatal;
		}

		goto end_nosignal;
	}
	case LTTNG_CONSUMER_DATA_PENDING:
	{
		int32_t ret;
		uint64_t id = msg.u.data_pending.session_id;

		DBG("Kernel consumer data pending command for id %" PRIu64, id);

		ret = consumer_data_pending(id);

		health_code_update();

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &ret, sizeof(ret));
		if (ret < 0) {
			PERROR("send data pending ret code");
			goto error_fatal;
		}

		/*
		 * No need to send back a status message since the data pending
		 * returned value is the response.
		 */
		break;
	}
	case LTTNG_CONSUMER_SNAPSHOT_CHANNEL:
	{
		if (msg.u.snapshot_channel.metadata == 1) {
			ret = lttng_kconsumer_snapshot_metadata(msg.u.snapshot_channel.key,
					msg.u.snapshot_channel.pathname,
					msg.u.snapshot_channel.relayd_id, ctx);
			if (ret < 0) {
				ERR("Snapshot metadata failed");
				ret_code = LTTCOMM_CONSUMERD_ERROR_METADATA;
			}
		} else {
			ret = lttng_kconsumer_snapshot_channel(msg.u.snapshot_channel.key,
					msg.u.snapshot_channel.pathname,
					msg.u.snapshot_channel.relayd_id,
					msg.u.snapshot_channel.nb_packets_per_stream,
					ctx);
			if (ret < 0) {
				ERR("Snapshot channel failed");
				ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
			}
		}

		health_code_update();

		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}
		break;
	}
	case LTTNG_CONSUMER_DESTROY_CHANNEL:
	{
		uint64_t key = msg.u.destroy_channel.key;
		struct lttng_consumer_channel *channel;

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Kernel consumer destroy channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		}

		health_code_update();

		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}

		health_code_update();

		/* Stop right now if no channel was found. */
		if (!channel) {
			goto end_nosignal;
		}

		/*
		 * This command should ONLY be issued for channel with streams set in
		 * no monitor mode.
		 */
		assert(!channel->monitor);

		/*
		 * The refcount should ALWAYS be 0 in the case of a channel in no
		 * monitor mode.
		 */
		assert(!uatomic_sub_return(&channel->refcount, 1));

		consumer_del_channel(channel);

		goto end_nosignal;
	}
	case LTTNG_CONSUMER_DISCARDED_EVENTS:
	{
		ssize_t ret;
		uint64_t count;
		struct lttng_consumer_channel *channel;
		uint64_t id = msg.u.discarded_events.session_id;
		uint64_t key = msg.u.discarded_events.channel_key;

		DBG("Kernel consumer discarded events command for session id %"
				PRIu64 ", channel key %" PRIu64, id, key);

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Kernel consumer discarded events channel %"
					PRIu64 " not found", key);
			count = 0;
		} else {
			count = channel->discarded_events;
		}

		health_code_update();

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &count, sizeof(count));
		if (ret < 0) {
			PERROR("send discarded events");
			goto error_fatal;
		}

		break;
	}
	case LTTNG_CONSUMER_LOST_PACKETS:
	{
		ssize_t ret;
		uint64_t count;
		struct lttng_consumer_channel *channel;
		uint64_t id = msg.u.lost_packets.session_id;
		uint64_t key = msg.u.lost_packets.channel_key;

		DBG("Kernel consumer lost packets command for session id %"
				PRIu64 ", channel key %" PRIu64, id, key);

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Kernel consumer lost packets channel %"
					PRIu64 " not found", key);
			count = 0;
		} else {
			count = channel->lost_packets;
		}

		health_code_update();

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &count, sizeof(count));
		if (ret < 0) {
			PERROR("send lost packets");
			goto error_fatal;
		}

		break;
	}
	case LTTNG_CONSUMER_SET_CHANNEL_MONITOR_PIPE:
	{
		int channel_monitor_pipe;

		ret_code = LTTCOMM_CONSUMERD_SUCCESS;
		/* Successfully received the command's type. */
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			goto error_fatal;
		}

		ret = lttcomm_recv_fds_unix_sock(sock, &channel_monitor_pipe,
				1);
		if (ret != sizeof(channel_monitor_pipe)) {
			ERR("Failed to receive channel monitor pipe");
			goto error_fatal;
		}

		DBG("Received channel monitor pipe (%d)", channel_monitor_pipe);
		ret = consumer_timer_thread_set_channel_monitor_pipe(
				channel_monitor_pipe);
		if (!ret) {
			int flags;

			ret_code = LTTCOMM_CONSUMERD_SUCCESS;
			/* Set the pipe as non-blocking. */
			ret = fcntl(channel_monitor_pipe, F_GETFL, 0);
			if (ret == -1) {
				PERROR("fcntl get flags of the channel monitoring pipe");
				goto error_fatal;
			}
			flags = ret;

			ret = fcntl(channel_monitor_pipe, F_SETFL,
					flags | O_NONBLOCK);
			if (ret == -1) {
				PERROR("fcntl set O_NONBLOCK flag of the channel monitoring pipe");
				goto error_fatal;
			}
			DBG("Channel monitor pipe set as non-blocking");
		} else {
			ret_code = LTTCOMM_CONSUMERD_ALREADY_SET;
		}
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			goto error_fatal;
		}
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
	health_code_update();
	return 1;

error_fatal:
	rcu_read_unlock();
	/* This will issue a consumer stop. */
	return -1;
}

/*
 * Populate index values of a kernel stream. Values are set in big endian order.
 *
 * Return 0 on success or else a negative value.
 */
static int get_index_values(struct ctf_packet_index *index, int infd)
{
	int ret;

	ret = kernctl_get_timestamp_begin(infd, &index->timestamp_begin);
	if (ret < 0) {
		PERROR("kernctl_get_timestamp_begin");
		goto error;
	}
	index->timestamp_begin = htobe64(index->timestamp_begin);

	ret = kernctl_get_timestamp_end(infd, &index->timestamp_end);
	if (ret < 0) {
		PERROR("kernctl_get_timestamp_end");
		goto error;
	}
	index->timestamp_end = htobe64(index->timestamp_end);

	ret = kernctl_get_events_discarded(infd, &index->events_discarded);
	if (ret < 0) {
		PERROR("kernctl_get_events_discarded");
		goto error;
	}
	index->events_discarded = htobe64(index->events_discarded);

	ret = kernctl_get_content_size(infd, &index->content_size);
	if (ret < 0) {
		PERROR("kernctl_get_content_size");
		goto error;
	}
	index->content_size = htobe64(index->content_size);

	ret = kernctl_get_packet_size(infd, &index->packet_size);
	if (ret < 0) {
		PERROR("kernctl_get_packet_size");
		goto error;
	}
	index->packet_size = htobe64(index->packet_size);

	ret = kernctl_get_stream_id(infd, &index->stream_id);
	if (ret < 0) {
		PERROR("kernctl_get_stream_id");
		goto error;
	}
	index->stream_id = htobe64(index->stream_id);

	ret = kernctl_get_instance_id(infd, &index->stream_instance_id);
	if (ret < 0) {
		if (ret == -ENOTTY) {
			/* Command not implemented by lttng-modules. */
			index->stream_instance_id = -1ULL;
		} else {
			PERROR("kernctl_get_instance_id");
			goto error;
		}
	}
	index->stream_instance_id = htobe64(index->stream_instance_id);

	ret = kernctl_get_sequence_number(infd, &index->packet_seq_num);
	if (ret < 0) {
		if (ret == -ENOTTY) {
			/* Command not implemented by lttng-modules. */
			index->packet_seq_num = -1ULL;
			ret = 0;
		} else {
			PERROR("kernctl_get_sequence_number");
			goto error;
		}
	}
	index->packet_seq_num = htobe64(index->packet_seq_num);

error:
	return ret;
}
/*
 * Sync metadata meaning request them to the session daemon and snapshot to the
 * metadata thread can consumer them.
 *
 * Metadata stream lock MUST be acquired.
 *
 * Return 0 if new metadatda is available, EAGAIN if the metadata stream
 * is empty or a negative value on error.
 */
int lttng_kconsumer_sync_metadata(struct lttng_consumer_stream *metadata)
{
	int ret;

	assert(metadata);

	ret = kernctl_buffer_flush(metadata->wait_fd);
	if (ret < 0) {
		ERR("Failed to flush kernel stream");
		goto end;
	}

	ret = kernctl_snapshot(metadata->wait_fd);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			ERR("Sync metadata, taking kernel snapshot failed.");
			goto end;
		}
		DBG("Sync metadata, no new kernel metadata");
		/* No new metadata, exit. */
		ret = ENODATA;
		goto end;
	}

end:
	return ret;
}

static
int update_stream_stats(struct lttng_consumer_stream *stream)
{
	int ret;
	uint64_t seq, discarded;

	ret = kernctl_get_sequence_number(stream->wait_fd, &seq);
	if (ret < 0) {
		if (ret == -ENOTTY) {
			/* Command not implemented by lttng-modules. */
			seq = -1ULL;
		} else {
			PERROR("kernctl_get_sequence_number");
			goto end;
		}
	}

	/*
	 * Start the sequence when we extract the first packet in case we don't
	 * start at 0 (for example if a consumer is not connected to the
	 * session immediately after the beginning).
	 */
	if (stream->last_sequence_number == -1ULL) {
		stream->last_sequence_number = seq;
	} else if (seq > stream->last_sequence_number) {
		stream->chan->lost_packets += seq -
				stream->last_sequence_number - 1;
	} else {
		/* seq <= last_sequence_number */
		ERR("Sequence number inconsistent : prev = %" PRIu64
				", current = %" PRIu64,
				stream->last_sequence_number, seq);
		ret = -1;
		goto end;
	}
	stream->last_sequence_number = seq;

	ret = kernctl_get_events_discarded(stream->wait_fd, &discarded);
	if (ret < 0) {
		PERROR("kernctl_get_events_discarded");
		goto end;
	}
	if (discarded < stream->last_discarded_events) {
		/*
		 * Overflow has occurred. We assume only one wrap-around
		 * has occurred.
		 */
		stream->chan->discarded_events += (1ULL << (CAA_BITS_PER_LONG - 1)) -
			stream->last_discarded_events + discarded;
	} else {
		stream->chan->discarded_events += discarded -
			stream->last_discarded_events;
	}
	stream->last_discarded_events = discarded;
	ret = 0;

end:
	return ret;
}

/*
 * Check if the local version of the metadata stream matches with the version
 * of the metadata stream in the kernel. If it was updated, set the reset flag
 * on the stream.
 */
static
int metadata_stream_check_version(int infd, struct lttng_consumer_stream *stream)
{
	int ret;
	uint64_t cur_version;

	ret = kernctl_get_metadata_version(infd, &cur_version);
	if (ret < 0) {
		if (ret == -ENOTTY) {
			/*
			 * LTTng-modules does not implement this
			 * command.
			 */
			ret = 0;
			goto end;
		}
		ERR("Failed to get the metadata version");
		goto end;
	}

	if (stream->metadata_version == cur_version) {
		ret = 0;
		goto end;
	}

	DBG("New metadata version detected");
	stream->metadata_version = cur_version;
	stream->reset_metadata_flag = 1;
	ret = 0;

end:
	return ret;
}

/*
 * Consume data on a file descriptor and write it on a trace file.
 */
ssize_t lttng_kconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	unsigned long len, subbuf_size, padding;
	int err, write_index = 1;
	ssize_t ret = 0;
	int infd = stream->wait_fd;
	struct ctf_packet_index index;

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
		ret = err;
		goto end;
	}

	/* Get the full subbuffer size including padding */
	err = kernctl_get_padded_subbuf_size(infd, &len);
	if (err != 0) {
		PERROR("Getting sub-buffer len failed.");
		err = kernctl_put_subbuf(infd);
		if (err != 0) {
			if (err == -EFAULT) {
				PERROR("Error in unreserving sub buffer\n");
			} else if (err == -EIO) {
				/* Should never happen with newer LTTng versions */
				PERROR("Reader has been pushed by the writer, last sub-buffer corrupted.");
			}
			ret = err;
			goto end;
		}
		ret = err;
		goto end;
	}

	if (!stream->metadata_flag) {
		ret = get_index_values(&index, infd);
		if (ret < 0) {
			err = kernctl_put_subbuf(infd);
			if (err != 0) {
				if (err == -EFAULT) {
					PERROR("Error in unreserving sub buffer\n");
				} else if (err == -EIO) {
					/* Should never happen with newer LTTng versions */
					PERROR("Reader has been pushed by the writer, last sub-buffer corrupted.");
				}
				ret = err;
				goto end;
			}
			goto end;
		}
		ret = update_stream_stats(stream);
		if (ret < 0) {
			err = kernctl_put_subbuf(infd);
			if (err != 0) {
				if (err == -EFAULT) {
					PERROR("Error in unreserving sub buffer\n");
				} else if (err == -EIO) {
					/* Should never happen with newer LTTng versions */
					PERROR("Reader has been pushed by the writer, last sub-buffer corrupted.");
				}
				ret = err;
				goto end;
			}
			goto end;
		}
	} else {
		write_index = 0;
		ret = metadata_stream_check_version(infd, stream);
		if (ret < 0) {
			err = kernctl_put_subbuf(infd);
			if (err != 0) {
				if (err == -EFAULT) {
					PERROR("Error in unreserving sub buffer\n");
				} else if (err == -EIO) {
					/* Should never happen with newer LTTng versions */
					PERROR("Reader has been pushed by the writer, last sub-buffer corrupted.");
				}
				ret = err;
				goto end;
			}
			goto end;
		}
	}

	switch (stream->chan->output) {
	case CONSUMER_CHANNEL_SPLICE:
		/*
		 * XXX: The lttng-modules splice "actor" does not handle copying
		 * partial pages hence only using the subbuffer size without the
		 * padding makes the splice fail.
		 */
		subbuf_size = len;
		padding = 0;

		/* splice the subbuffer to the tracefile */
		ret = lttng_consumer_on_read_subbuffer_splice(ctx, stream, subbuf_size,
				padding, &index);
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
			write_index = 0;
		}
		break;
	case CONSUMER_CHANNEL_MMAP:
		/* Get subbuffer size without padding */
		err = kernctl_get_subbuf_size(infd, &subbuf_size);
		if (err != 0) {
			PERROR("Getting sub-buffer len failed.");
			err = kernctl_put_subbuf(infd);
			if (err != 0) {
				if (err == -EFAULT) {
					PERROR("Error in unreserving sub buffer\n");
				} else if (err == -EIO) {
					/* Should never happen with newer LTTng versions */
					PERROR("Reader has been pushed by the writer, last sub-buffer corrupted.");
				}
				ret = err;
				goto end;
			}
			ret = err;
			goto end;
		}

		/* Make sure the tracer is not gone mad on us! */
		assert(len >= subbuf_size);

		padding = len - subbuf_size;

		/* write the subbuffer to the tracefile */
		ret = lttng_consumer_on_read_subbuffer_mmap(ctx, stream, subbuf_size,
				padding, &index);
		/*
		 * The mmap operation should write subbuf_size amount of data when
		 * network streaming or the full padding (len) size when we are _not_
		 * streaming.
		 */
		if ((ret != subbuf_size && stream->net_seq_idx != (uint64_t) -1ULL) ||
				(ret != len && stream->net_seq_idx == (uint64_t) -1ULL)) {
			/*
			 * Display the error but continue processing to try to release the
			 * subbuffer. This is a DBG statement since this is possible to
			 * happen without being a critical error.
			 */
			DBG("Error writing to tracefile "
					"(ret: %zd != len: %lu != subbuf_size: %lu)",
					ret, len, subbuf_size);
			write_index = 0;
		}
		break;
	default:
		ERR("Unknown output method");
		ret = -EPERM;
	}

	err = kernctl_put_next_subbuf(infd);
	if (err != 0) {
		if (err == -EFAULT) {
			PERROR("Error in unreserving sub buffer\n");
		} else if (err == -EIO) {
			/* Should never happen with newer LTTng versions */
			PERROR("Reader has been pushed by the writer, last sub-buffer corrupted.");
		}
		ret = err;
		goto end;
	}

	/* Write index if needed. */
	if (!write_index) {
		goto end;
	}

	if (stream->chan->live_timer_interval && !stream->metadata_flag) {
		/*
		 * In live, block until all the metadata is sent.
		 */
		pthread_mutex_lock(&stream->metadata_timer_lock);
		assert(!stream->missed_metadata_flush);
		stream->waiting_on_metadata = true;
		pthread_mutex_unlock(&stream->metadata_timer_lock);

		err = consumer_stream_sync_metadata(ctx, stream->session_id);

		pthread_mutex_lock(&stream->metadata_timer_lock);
		stream->waiting_on_metadata = false;
		if (stream->missed_metadata_flush) {
			stream->missed_metadata_flush = false;
			pthread_mutex_unlock(&stream->metadata_timer_lock);
			(void) consumer_flush_kernel_index(stream);
		} else {
			pthread_mutex_unlock(&stream->metadata_timer_lock);
		}
		if (err < 0) {
			goto end;
		}
	}

	err = consumer_stream_write_index(stream, &index);
	if (err < 0) {
		goto end;
	}

end:
	return ret;
}

int lttng_kconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);

	/*
	 * Don't create anything if this is set for streaming or should not be
	 * monitored.
	 */
	if (stream->net_seq_idx == (uint64_t) -1ULL && stream->chan->monitor) {
		ret = utils_create_stream_file(stream->chan->pathname, stream->name,
				stream->chan->tracefile_size, stream->tracefile_count_current,
				stream->uid, stream->gid, NULL);
		if (ret < 0) {
			goto error;
		}
		stream->out_fd = ret;
		stream->tracefile_size_current = 0;

		if (!stream->metadata_flag) {
			struct lttng_index_file *index_file;

			index_file = lttng_index_file_create(stream->chan->pathname,
					stream->name, stream->uid, stream->gid,
					stream->chan->tracefile_size,
					stream->tracefile_count_current,
					CTF_INDEX_MAJOR, CTF_INDEX_MINOR);
			if (!index_file) {
				goto error;
			}
			assert(!stream->index_file);
			stream->index_file = index_file;
		}
	}

	if (stream->output == LTTNG_EVENT_MMAP) {
		/* get the len of the mmap region */
		unsigned long mmap_len;

		ret = kernctl_get_mmap_len(stream->wait_fd, &mmap_len);
		if (ret != 0) {
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
	if (stream->out_fd >= 0) {
		int err;

		err = close(stream->out_fd);
		assert(!err);
		stream->out_fd = -1;
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

	if (stream->endpoint_status != CONSUMER_ENDPOINT_ACTIVE) {
		ret = 0;
		goto end;
	}

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
