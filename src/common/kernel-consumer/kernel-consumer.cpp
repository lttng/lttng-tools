/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "kernel-consumer.hpp"

#include <common/buffer-view.hpp>
#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/consumer/consumer-stream.hpp>
#include <common/consumer/consumer-timer.hpp>
#include <common/consumer/consumer.hpp>
#include <common/consumer/metadata-bucket.hpp>
#include <common/index/index.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/optional.hpp>
#include <common/pipe.hpp>
#include <common/pthread-lock.hpp>
#include <common/relayd/relayd.hpp>
#include <common/scope-exit.hpp>
#include <common/sessiond-comm/relayd.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <bin/lttng-consumerd/health-consumerd.hpp>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

extern struct lttng_consumer_global_data the_consumer_data;
extern int consumer_poll_timeout;

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_take_snapshot(struct lttng_consumer_stream *stream)
{
	int ret = 0;
	const int infd = stream->wait_fd;

	ret = kernctl_snapshot(infd);
	/*
	 * -EAGAIN is not an error, it just means that there is no data to
	 *  be read.
	 */
	if (ret != 0 && ret != -EAGAIN) {
		PERROR("Getting sub-buffer snapshot.");
	}

	return ret;
}

/*
 * Sample consumed and produced positions for a specific fd.
 *
 * Returns 0 on success, < 0 on error.
 */
int lttng_kconsumer_sample_snapshot_positions(struct lttng_consumer_stream *stream)
{
	LTTNG_ASSERT(stream);

	return kernctl_snapshot_sample_positions(stream->wait_fd);
}

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_get_produced_snapshot(struct lttng_consumer_stream *stream, unsigned long *pos)
{
	int ret;
	const int infd = stream->wait_fd;

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
int lttng_kconsumer_get_consumed_snapshot(struct lttng_consumer_stream *stream, unsigned long *pos)
{
	int ret;
	const int infd = stream->wait_fd;

	ret = kernctl_snapshot_get_consumed(infd, pos);
	if (ret != 0) {
		PERROR("kernctl_snapshot_get_consumed");
	}

	return ret;
}

static int get_current_subbuf_addr(struct lttng_consumer_stream *stream, const char **addr)
{
	int ret;
	unsigned long mmap_offset;
	const char *mmap_base = (const char *) stream->mmap_base;

	ret = kernctl_get_mmap_read_offset(stream->wait_fd, &mmap_offset);
	if (ret < 0) {
		PERROR("Failed to get mmap read offset");
		goto error;
	}

	*addr = mmap_base + mmap_offset;
error:
	return ret;
}

/*
 * Take a snapshot of all the stream of a channel
 * RCU read-side lock must be held across this function to ensure existence of
 * channel.
 *
 * Returns 0 on success, < 0 on error
 */
static int lttng_kconsumer_snapshot_channel(struct lttng_consumer_channel *channel,
					    uint64_t key,
					    char *path,
					    uint64_t relayd_id,
					    uint64_t nb_packets_per_stream)
{
	int ret;
	std::vector<uint8_t> packet_buffer;
	static bool warn_flush_or_populate_packet = false, warn_flush = false;

	DBG("Kernel consumer snapshot channel %" PRIu64, key);

	/* Prevent channel modifications while we perform the snapshot. */
	const lttng::pthread::lock_guard channe_lock(channel->lock);

	const lttng::urcu::read_lock_guard read_lock;

	/* Splice is not supported yet for channel snapshot. */
	if (channel->output != CONSUMER_CHANNEL_MMAP) {
		ERR("Unsupported output type for channel \"%s\": mmap output is required to record a snapshot",
		    channel->name);
		return -1;
	}

	for (auto stream : lttng::urcu::list_iteration_adapter<lttng_consumer_stream,
							       &lttng_consumer_stream::send_node>(
		     channel->streams.head)) {
		unsigned long consumed_pos, produced_pos, max_subbuf_size;
		lttng_kernel_abi_ring_buffer_packet_flush_or_populate_packet_args packet_args = {};

		health_code_update();

		/*
		 * Lock stream because we are about to change its state.
		 */
		const lttng::pthread::lock_guard stream_lock(stream->lock);

		LTTNG_ASSERT(channel->trace_chunk);
		if (!lttng_trace_chunk_get(channel->trace_chunk)) {
			/*
			 * Can't happen barring an internal error as the channel
			 * holds a reference to the trace chunk.
			 */
			ERR("Failed to acquire reference to channel's trace chunk");
			return -1;
		}

		LTTNG_ASSERT(!stream->trace_chunk);
		stream->trace_chunk = channel->trace_chunk;

		/*
		 * Assign the received relayd ID so we can use it for streaming. The streams
		 * are not visible to anyone so this is OK to change it.
		 */
		stream->net_seq_idx = relayd_id;
		channel->relayd_id = relayd_id;

		/* Close stream output when were are done. */
		const auto close_stream_output = lttng::make_scope_exit(
			[stream]() noexcept { consumer_stream_close_output(stream); });

		if (relayd_id != (uint64_t) -1ULL) {
			ret = consumer_send_relayd_stream(stream, path);
			if (ret < 0) {
				ERR("sending stream to relayd");
				return ret;
			}
		} else {
			ret = consumer_stream_create_output_files(stream, false);
			if (ret < 0) {
				return ret;
			}

			DBG("Kernel consumer snapshot stream (%" PRIu64 ")", stream->key);
		}

		ret = kernctl_get_max_subbuf_size(stream->wait_fd, &max_subbuf_size);
		if (ret < 0) {
			ERR("Failed to get max subbuf_size: %d", ret);
			return ret;
		}

		try {
			packet_buffer.resize(static_cast<size_t>(max_subbuf_size));
		} catch (const std::bad_alloc& e) {
			ERR("Failed to allocate `%ld` bytes for packet", max_subbuf_size);
			return -ENOMEM;
		}

		packet_args.packet =
			static_cast<uint64_t>(reinterpret_cast<uintptr_t>(packet_buffer.data()));

		ret = kernctl_buffer_flush_or_populate_packet(stream->wait_fd, &packet_args);
		if (ret < 0) {
			if (ret != -ENOTTY) {
				/* kernctl_buffer_flush_or_poopulate_packet is supported, but failed
				 */
				ERR("kernctl_buffer_flush_or_populate_packet failed (%d)", ret);
				return ret;
			}

			if (!warn_flush_or_populate_packet) {
				DBG("kernctl_buffer_flush_or_populate_packet failed (%d)", ret);
				WARN("kernctl_buffer_flush_or_populate_packet is not available: older flushes will be used. Multiple subsequent snapshots may overwrite buffers for streams with no new events.");
				warn_flush_or_populate_packet = true;
			}

			ret = kernctl_buffer_flush_empty(stream->wait_fd);
			if (ret < 0) {
				if (!warn_flush) {
					DBG("Failed to perform kernctl_buffer_flush_empty: %d",
					    ret);
					WARN("kernctl_buffer_flush_empty is not available. Older flush will be used. Clients reading produced traces will not be able to do stream intersection on streams with no new events.");
					warn_flush = true;
				}
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
					return ret;
				}
			}
		}

		ret = lttng_kconsumer_take_snapshot(stream);
		if (ret < 0) {
			ERR("Taking kernel snapshot");
			return ret;
		}

		ret = lttng_kconsumer_get_produced_snapshot(stream, &produced_pos);
		if (ret < 0) {
			ERR("Produced kernel snapshot position");
			return ret;
		}

		ret = lttng_kconsumer_get_consumed_snapshot(stream, &consumed_pos);
		if (ret < 0) {
			ERR("Consumerd kernel snapshot position");
			return ret;
		}

		consumed_pos = consumer_get_consume_start_pos(
			consumed_pos, produced_pos, nb_packets_per_stream, stream->max_sb_size);

		while ((long) (consumed_pos - produced_pos) < 0) {
			ssize_t read_len;
			unsigned long len, padded_len;
			const char *subbuf_addr;
			struct lttng_buffer_view subbuf_view;

			health_code_update();
			DBG("Kernel consumer taking snapshot at pos %lu", consumed_pos);

			ret = kernctl_get_subbuf(stream->wait_fd, &consumed_pos);
			if (ret < 0) {
				if (ret != -EAGAIN) {
					PERROR("kernctl_get_subbuf snapshot");
					return ret;
				}

				DBG("Kernel consumer get subbuf failed. Skipping it.");
				consumed_pos += stream->max_sb_size;
				stream->chan->lost_packets++;
				continue;
			}

			/* Put the subbuffer once we are done. */
			const auto put_subbuf = lttng::make_scope_exit([stream]() noexcept {
				const auto put_ret = kernctl_put_subbuf(stream->wait_fd);
				if (put_ret < 0) {
					ERR("Snapshot kernctl_put_subbuf");
				}
			});

			ret = kernctl_get_subbuf_size(stream->wait_fd, &len);
			if (ret < 0) {
				ERR("Snapshot kernctl_get_subbuf_size");
				return ret;
			}

			ret = kernctl_get_padded_subbuf_size(stream->wait_fd, &padded_len);
			if (ret < 0) {
				ERR("Snapshot kernctl_get_padded_subbuf_size");
				return ret;
			}

			ret = get_current_subbuf_addr(stream, &subbuf_addr);
			if (ret) {
				return ret;
			}

			subbuf_view = lttng_buffer_view_init(subbuf_addr, 0, padded_len);
			read_len = lttng_consumer_on_read_subbuffer_mmap(
				stream, &subbuf_view, padded_len - len);
			/*
			 * We write the padded len in local tracefiles but the data len
			 * when using a relay. Display the error but continue processing
			 * to try to release the subbuffer.
			 */
			if (relayd_id != (uint64_t) -1ULL) {
				if (read_len != len) {
					ERR("Error sending to the relay (ret: %zd != len: %lu)",
					    read_len,
					    len);
				}
			} else {
				if (read_len != padded_len) {
					ERR("Error writing to tracefile (ret: %zd != len: %lu)",
					    read_len,
					    padded_len);
				}
			}

			consumed_pos += stream->max_sb_size;
		}

		if (packet_args.packet_populated) {
			health_code_update();

			const auto subbuf_view = lttng_buffer_view_init(
				(char *) packet_buffer.data(), 0, packet_args.packet_length_padded);
			const auto read_len = lttng_consumer_on_read_subbuffer_mmap(
				stream,
				&subbuf_view,
				packet_args.packet_length_padded - packet_args.packet_length);

			/*
			 * We write the padded len in local tracefiles but the data len
			 * when using a relay. Display the error but continue processing.
			 */
			if (relayd_id != (uint64_t) -1ULL) {
				if (read_len != packet_args.packet_length) {
					ERR_FMT("Error sending to the relay (ret: {} != len: {})",
						read_len,
						+packet_args.packet_length);
					return -1;
				}
			} else {
				if (read_len != packet_args.packet_length_padded) {
					ERR_FMT("Error writing to tracefile (ret: {} != len: {})",
						read_len,
						+packet_args.packet_length_padded);
					return -1;
				}
			}
		}
	}

	/* All good! */
	return 0;
}

/*
 * Read the whole metadata available for a snapshot.
 * RCU read-side lock must be held across this function to ensure existence of
 * metadata_channel.
 *
 * Returns 0 on success, < 0 on error
 */
static int lttng_kconsumer_snapshot_metadata(struct lttng_consumer_channel *metadata_channel,
					     uint64_t key,
					     char *path,
					     uint64_t relayd_id,
					     struct lttng_consumer_local_data *ctx)
{
	int ret, use_relayd = 0;
	ssize_t ret_read;
	struct lttng_consumer_stream *metadata_stream;

	LTTNG_ASSERT(ctx);

	DBG("Kernel consumer snapshot metadata with key %" PRIu64 " at path %s", key, path);

	const lttng::urcu::read_lock_guard read_lock;

	metadata_stream = metadata_channel->metadata_stream;
	LTTNG_ASSERT(metadata_stream);

	metadata_stream->read_subbuffer_ops.lock(metadata_stream);
	LTTNG_ASSERT(metadata_channel->trace_chunk);
	LTTNG_ASSERT(metadata_stream->trace_chunk);

	/* Flag once that we have a valid relayd for the stream. */
	if (relayd_id != (uint64_t) -1ULL) {
		use_relayd = 1;
	}

	if (use_relayd) {
		ret = consumer_send_relayd_stream(metadata_stream, path);
		if (ret < 0) {
			goto error_snapshot;
		}
	} else {
		ret = consumer_stream_create_output_files(metadata_stream, false);
		if (ret < 0) {
			goto error_snapshot;
		}
	}

	do {
		health_code_update();

		ret_read = lttng_consumer_read_subbuffer(metadata_stream, ctx, true);
		if (ret_read < 0) {
			ERR("Kernel snapshot reading metadata subbuffer (ret: %zd)", ret_read);
			ret = ret_read;
			goto error_snapshot;
		}
	} while (ret_read > 0);

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
			lttng_trace_chunk_put(metadata_stream->trace_chunk);
			metadata_stream->trace_chunk = nullptr;
		}
	}

	ret = 0;
error_snapshot:
	metadata_stream->read_subbuffer_ops.unlock(metadata_stream);
	consumer_stream_destroy(metadata_stream, nullptr);
	metadata_channel->metadata_stream = nullptr;
	return ret;
}

/*
 * Receive command from session daemon and process it.
 *
 * Return 1 on success else a negative value or 0.
 */
int lttng_kconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
			     int sock,
			     struct pollfd *consumer_sockpoll)
{
	int ret_func;
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct lttcomm_consumer_msg msg;

	health_code_update();

	{
		ssize_t ret_recv;

		ret_recv = lttcomm_recv_unix_sock(sock, &msg, sizeof(msg));
		if (ret_recv != sizeof(msg)) {
			if (ret_recv > 0) {
				lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_CMD);
				ret_recv = -1;
			}
			return ret_recv;
		}
	}

	health_code_update();

	/* Deprecated command */
	LTTNG_ASSERT(msg.cmd_type != LTTNG_CONSUMER_STOP);

	health_code_update();

	/* relayd needs RCU read-side protection */
	const lttng::urcu::read_lock_guard read_lock;

	switch (msg.cmd_type) {
	case LTTNG_CONSUMER_ADD_RELAYD_SOCKET:
	{
		const uint32_t major = msg.u.relayd_sock.major;
		const uint32_t minor = msg.u.relayd_sock.minor;
		const lttcomm_sock_proto protocol =
			(enum lttcomm_sock_proto) msg.u.relayd_sock.relayd_socket_protocol;

		/* Session daemon status message are handled in the following call. */
		consumer_add_relayd_socket(msg.u.relayd_sock.net_index,
					   msg.u.relayd_sock.type,
					   ctx,
					   sock,
					   consumer_sockpoll,
					   msg.u.relayd_sock.session_id,
					   msg.u.relayd_sock.relayd_session_id,
					   major,
					   minor,
					   protocol);
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_ADD_CHANNEL:
	{
		struct lttng_consumer_channel *new_channel;
		int ret_send_status, ret_add_channel = 0;
		const uint64_t chunk_id = msg.u.channel.chunk_id.value;

		health_code_update();

		/* First send a status message before receiving the fds. */
		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_fatal;
		}

		health_code_update();

		DBG("consumer_add_channel %" PRIu64, msg.u.channel.channel_key);
		new_channel = consumer_allocate_channel(msg.u.channel.channel_key,
							msg.u.channel.session_id,
							msg.u.channel.chunk_id.is_set ? &chunk_id :
											nullptr,
							msg.u.channel.pathname,
							msg.u.channel.name,
							msg.u.channel.relayd_id,
							msg.u.channel.output,
							msg.u.channel.tracefile_size,
							msg.u.channel.tracefile_count,
							0,
							msg.u.channel.monitor,
							msg.u.channel.live_timer_interval,
							msg.u.channel.is_live,
							nullptr,
							nullptr);
		if (new_channel == nullptr) {
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
		case CONSUMER_CHANNEL_TYPE_DATA_PER_CPU:
			/* Fallthrough */
		case CONSUMER_CHANNEL_TYPE_METADATA:
			new_channel->type = (consumer_channel_type) msg.u.channel.type;
			break;
		case CONSUMER_CHANNEL_TYPE_DATA_PER_CHANNEL:
			ERR("Invalid channel type for kernel consumer");
			goto end_nosignal;
		default:
			abort();
			goto end_nosignal;
		};

		health_code_update();

		if (ctx->on_recv_channel != nullptr) {
			const int ret_recv_channel = ctx->on_recv_channel(new_channel);
			if (ret_recv_channel == 0) {
				ret_add_channel = consumer_add_channel(new_channel, ctx);
			} else if (ret_recv_channel < 0) {
				goto end_nosignal;
			}
		} else {
			ret_add_channel = consumer_add_channel(new_channel, ctx);
		}
		if (msg.u.channel.type == CONSUMER_CHANNEL_TYPE_DATA_PER_CPU && !ret_add_channel) {
			int monitor_start_ret;

			DBG("Consumer starting monitor timer");
			consumer_timer_live_start(new_channel, msg.u.channel.live_timer_interval);
			monitor_start_ret = consumer_timer_monitor_start(
				new_channel, msg.u.channel.monitor_timer_interval);
			if (monitor_start_ret < 0) {
				ERR("Starting channel monitoring timer failed");
				goto end_nosignal;
			}
		}

		health_code_update();

		/* If we received an error in add_channel, we need to report it. */
		if (ret_add_channel < 0) {
			ret_send_status = consumer_send_status_msg(sock, ret_add_channel);
			if (ret_send_status < 0) {
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
		int ret_send_status, ret_poll, ret_get_max_subbuf_size;
		ssize_t ret_pipe_write, ret_recv;

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
		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_add_stream_fatal;
		}

		health_code_update();

		if (ret_code != LTTCOMM_CONSUMERD_SUCCESS) {
			/* Channel was not found. */
			goto error_add_stream_nosignal;
		}

		/* Blocking call */
		health_poll_entry();
		ret_poll = lttng_consumer_poll_socket(consumer_sockpoll);
		health_poll_exit();
		if (ret_poll) {
			goto error_add_stream_fatal;
		}

		health_code_update();

		/* Get stream file descriptor from socket */
		ret_recv = lttcomm_recv_fds_unix_sock(sock, &fd, 1);
		if (ret_recv != sizeof(fd)) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
			ret_func = ret_recv;
			goto end;
		}

		health_code_update();

		/*
		 * Send status code to session daemon only if the recv works. If the
		 * above recv() failed, the session daemon is notified through the
		 * error socket and the teardown is eventually done.
		 */
		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_add_stream_nosignal;
		}

		health_code_update();

		pthread_mutex_lock(&channel->lock);
		new_stream = consumer_stream_create(channel,
						    channel->key,
						    fd,
						    channel->name,
						    channel->relayd_id,
						    channel->session_id,
						    channel->trace_chunk,
						    msg.u.stream.cpu,
						    &alloc_ret,
						    channel->type,
						    channel->monitor);
		if (new_stream == nullptr) {
			switch (alloc_ret) {
			case -ENOMEM:
			case -EINVAL:
			default:
				lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
				break;
			}
			pthread_mutex_unlock(&channel->lock);
			goto error_add_stream_nosignal;
		}

		new_stream->wait_fd = fd;
		ret_get_max_subbuf_size =
			kernctl_get_max_subbuf_size(new_stream->wait_fd, &new_stream->max_sb_size);
		if (ret_get_max_subbuf_size < 0) {
			pthread_mutex_unlock(&channel->lock);
			ERR("Failed to get kernel maximal subbuffer size");
			goto error_add_stream_nosignal;
		}

		consumer_stream_update_channel_attributes(new_stream, channel);

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

		pthread_mutex_lock(&new_stream->lock);
		if (ctx->on_recv_stream) {
			const int ret_recv_stream = ctx->on_recv_stream(new_stream);
			if (ret_recv_stream < 0) {
				pthread_mutex_unlock(&new_stream->lock);
				pthread_mutex_unlock(&channel->lock);
				consumer_stream_free(new_stream);
				goto error_add_stream_nosignal;
			}
		}
		health_code_update();

		if (new_stream->metadata_flag) {
			channel->metadata_stream = new_stream;
		}

		/* Do not monitor this stream. */
		if (!channel->monitor) {
			DBG("Kernel consumer add stream %s in no monitor mode with "
			    "relayd id %" PRIu64,
			    new_stream->name,
			    new_stream->net_seq_idx);
			cds_list_add(&new_stream->send_node, &channel->streams.head);
			pthread_mutex_unlock(&new_stream->lock);
			pthread_mutex_unlock(&channel->lock);
			goto end_add_stream;
		}

		/* Send stream to relayd if the stream has an ID. */
		if (new_stream->net_seq_idx != (uint64_t) -1ULL) {
			int ret_send_relayd_stream;

			ret_send_relayd_stream =
				consumer_send_relayd_stream(new_stream, new_stream->chan->pathname);
			if (ret_send_relayd_stream < 0) {
				pthread_mutex_unlock(&new_stream->lock);
				pthread_mutex_unlock(&channel->lock);
				consumer_stream_free(new_stream);
				goto error_add_stream_nosignal;
			}

			/*
			 * If adding an extra stream to an already
			 * existing channel (e.g. cpu hotplug), we need
			 * to send the "streams_sent" command to relayd.
			 */
			if (channel->streams_sent_to_relayd) {
				int ret_send_relayd_streams_sent;

				ret_send_relayd_streams_sent =
					consumer_send_relayd_streams_sent(new_stream->net_seq_idx);
				if (ret_send_relayd_streams_sent < 0) {
					pthread_mutex_unlock(&new_stream->lock);
					pthread_mutex_unlock(&channel->lock);
					goto error_add_stream_nosignal;
				}
			}
		}
		pthread_mutex_unlock(&new_stream->lock);
		pthread_mutex_unlock(&channel->lock);

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

		ret_pipe_write =
			lttng_pipe_write(stream_pipe, &new_stream, sizeof(new_stream)); /* NOLINT
											   sizeof
											   used on a
											   pointer.
											 */
		if (ret_pipe_write < 0) {
			ERR("Consumer write %s stream to pipe %d",
			    new_stream->metadata_flag ? "metadata" : "data",
			    lttng_pipe_get_writefd(stream_pipe));
			if (new_stream->metadata_flag) {
				consumer_del_stream_for_metadata(new_stream);
			} else {
				consumer_del_stream_for_data(new_stream);
			}
			goto error_add_stream_nosignal;
		}

		DBG("Kernel consumer ADD_STREAM %s (fd: %d) %s with relayd id %" PRIu64,
		    new_stream->name,
		    fd,
		    new_stream->chan->pathname,
		    new_stream->relayd_stream_id);
	end_add_stream:
		break;
	error_add_stream_nosignal:
		goto end_nosignal;
	error_add_stream_fatal:
		goto error_fatal;
	}
	case LTTNG_CONSUMER_STREAMS_SENT:
	{
		struct lttng_consumer_channel *channel;
		int ret_send_status;

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
			ERR("Unable to find channel key %" PRIu64, msg.u.sent_streams.channel_key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		}

		health_code_update();

		/*
		 * Send status code to session daemon.
		 */
		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0 || ret_code != LTTCOMM_CONSUMERD_SUCCESS) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_streams_sent_nosignal;
		}

		health_code_update();

		/*
		 * We should not send this message if we don't monitor the
		 * streams in this channel.
		 */
		if (!channel->monitor) {
			goto end_error_streams_sent;
		}

		health_code_update();
		/* Send stream to relayd if the stream has an ID. */
		if (msg.u.sent_streams.net_seq_idx != (uint64_t) -1ULL) {
			int ret_send_relay_streams;

			ret_send_relay_streams =
				consumer_send_relayd_streams_sent(msg.u.sent_streams.net_seq_idx);
			if (ret_send_relay_streams < 0) {
				goto error_streams_sent_nosignal;
			}
			channel->streams_sent_to_relayd = true;
		}
	end_error_streams_sent:
		break;
	error_streams_sent_nosignal:
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_UPDATE_STREAM:
	{
		return -ENOSYS;
	}
	case LTTNG_CONSUMER_DESTROY_RELAYD:
	{
		const uint64_t index = msg.u.destroy_relayd.net_seq_idx;
		struct consumer_relayd_sock_pair *relayd;
		int ret_send_status;

		DBG("Kernel consumer destroying relayd %" PRIu64, index);

		/* Get relayd reference if exists. */
		relayd = consumer_find_relayd(index);
		if (relayd == nullptr) {
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

		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_fatal;
		}

		goto end_nosignal;
	}
	case LTTNG_CONSUMER_DATA_PENDING:
	{
		int32_t ret_data_pending;
		const uint64_t id = msg.u.data_pending.session_id;
		ssize_t ret_send;

		DBG("Kernel consumer data pending command for id %" PRIu64, id);

		ret_data_pending = consumer_data_pending(id);

		health_code_update();

		/* Send back returned value to session daemon */
		ret_send =
			lttcomm_send_unix_sock(sock, &ret_data_pending, sizeof(ret_data_pending));
		if (ret_send < 0) {
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
		struct lttng_consumer_channel *channel;
		const uint64_t key = msg.u.snapshot_channel.key;
		int ret_send_status;

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		} else {
			if (msg.u.snapshot_channel.metadata == 1) {
				int ret_snapshot;

				ret_snapshot = lttng_kconsumer_snapshot_metadata(
					channel,
					key,
					msg.u.snapshot_channel.pathname,
					msg.u.snapshot_channel.relayd_id,
					ctx);
				if (ret_snapshot < 0) {
					ERR("Snapshot metadata failed");
					ret_code = LTTCOMM_CONSUMERD_SNAPSHOT_FAILED;
				}
			} else {
				int ret_snapshot;

				ret_snapshot = lttng_kconsumer_snapshot_channel(
					channel,
					key,
					msg.u.snapshot_channel.pathname,
					msg.u.snapshot_channel.relayd_id,
					msg.u.snapshot_channel.nb_packets_per_stream);
				if (ret_snapshot < 0) {
					ERR("Snapshot channel failed");
					ret_code = LTTCOMM_CONSUMERD_SNAPSHOT_FAILED;
				}
			}
		}
		health_code_update();

		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}
		break;
	}
	case LTTNG_CONSUMER_DESTROY_CHANNEL:
	{
		const uint64_t key = msg.u.destroy_channel.key;
		struct lttng_consumer_channel *channel;
		int ret_send_status;

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Kernel consumer destroy channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		}

		health_code_update();

		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_destroy_channel;
		}

		health_code_update();

		/* Stop right now if no channel was found. */
		if (!channel) {
			goto end_destroy_channel;
		}

		/*
		 * This command should ONLY be issued for channel with streams set in
		 * no monitor mode.
		 */
		LTTNG_ASSERT(!channel->monitor);

		/*
		 * The refcount should ALWAYS be 0 in the case of a channel in no
		 * monitor mode.
		 */
		LTTNG_ASSERT(!uatomic_sub_return(&channel->refcount, 1));

		consumer_del_channel(channel);
	end_destroy_channel:
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_DISCARDED_EVENTS:
	{
		ssize_t ret;
		uint64_t count;
		struct lttng_consumer_channel *channel;
		const uint64_t id = msg.u.discarded_events.session_id;
		const uint64_t key = msg.u.discarded_events.channel_key;

		DBG("Kernel consumer discarded events command for session id %" PRIu64
		    ", channel key %" PRIu64,
		    id,
		    key);

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Kernel consumer discarded events channel %" PRIu64 " not found", key);
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
		const uint64_t id = msg.u.lost_packets.session_id;
		const uint64_t key = msg.u.lost_packets.channel_key;

		DBG("Kernel consumer lost packets command for session id %" PRIu64
		    ", channel key %" PRIu64,
		    id,
		    key);

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Kernel consumer lost packets channel %" PRIu64 " not found", key);
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
		int ret_send_status, ret_set_channel_monitor_pipe;
		ssize_t ret_recv;

		ret_code = LTTCOMM_CONSUMERD_SUCCESS;
		/* Successfully received the command's type. */
		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			goto error_fatal;
		}

		ret_recv = lttcomm_recv_fds_unix_sock(sock, &channel_monitor_pipe, 1);
		if (ret_recv != sizeof(channel_monitor_pipe)) {
			ERR("Failed to receive channel monitor pipe");
			goto error_fatal;
		}

		DBG("Received channel monitor pipe (%d)", channel_monitor_pipe);
		ret_set_channel_monitor_pipe =
			consumer_timer_thread_set_channel_monitor_pipe(channel_monitor_pipe);
		if (!ret_set_channel_monitor_pipe) {
			int flags;
			int ret_fcntl;

			ret_code = LTTCOMM_CONSUMERD_SUCCESS;
			/* Set the pipe as non-blocking. */
			ret_fcntl = fcntl(channel_monitor_pipe, F_GETFL, 0);
			if (ret_fcntl == -1) {
				PERROR("fcntl get flags of the channel monitoring pipe");
				goto error_fatal;
			}
			flags = ret_fcntl;

			ret_fcntl = fcntl(channel_monitor_pipe, F_SETFL, flags | O_NONBLOCK);
			if (ret_fcntl == -1) {
				PERROR("fcntl set O_NONBLOCK flag of the channel monitoring pipe");
				goto error_fatal;
			}
			DBG("Channel monitor pipe set as non-blocking");
		} else {
			ret_code = LTTCOMM_CONSUMERD_ALREADY_SET;
		}
		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			goto error_fatal;
		}
		break;
	}
	case LTTNG_CONSUMER_ROTATE_CHANNEL:
	{
		struct lttng_consumer_channel *channel;
		const uint64_t key = msg.u.rotate_channel.key;
		int ret_send_status;

		DBG("Consumer rotate channel %" PRIu64, key);

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("Channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		} else {
			/*
			 * Sample the rotate position of all the streams in this channel.
			 */
			int ret_rotate_channel;

			ret_rotate_channel = lttng_consumer_rotate_channel(
				channel, key, msg.u.rotate_channel.relayd_id);
			if (ret_rotate_channel < 0) {
				ERR("Rotate channel failed");
				ret_code = LTTCOMM_CONSUMERD_ROTATION_FAIL;
			}

			health_code_update();
		}

		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_rotate_channel;
		}
		if (channel) {
			/* Rotate the streams that are ready right now. */
			int ret_rotate;

			ret_rotate = lttng_consumer_rotate_ready_streams(channel, key);
			if (ret_rotate < 0) {
				ERR("Rotate ready streams failed");
			}
		}
		break;
	error_rotate_channel:
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_CLEAR_CHANNEL:
	{
		struct lttng_consumer_channel *channel;
		const uint64_t key = msg.u.clear_channel.key;
		int ret_send_status;

		channel = consumer_find_channel(key);
		if (!channel) {
			DBG("Channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		} else {
			int ret_clear_channel;

			ret_clear_channel = lttng_consumer_clear_channel(channel);
			if (ret_clear_channel) {
				ERR("Clear channel failed");
				ret_code = (lttcomm_return_code) ret_clear_channel;
			}

			health_code_update();
		}

		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}

		break;
	}
	case LTTNG_CONSUMER_INIT:
	{
		int ret_send_status;
		lttng_uuid sessiond_uuid;

		std::copy(std::begin(msg.u.init.sessiond_uuid),
			  std::end(msg.u.init.sessiond_uuid),
			  sessiond_uuid.begin());

		ret_code = lttng_consumer_init_command(ctx, sessiond_uuid);
		health_code_update();
		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}
		break;
	}
	case LTTNG_CONSUMER_CREATE_TRACE_CHUNK:
	{
		const struct lttng_credentials credentials = {
			.uid = LTTNG_OPTIONAL_INIT_VALUE(
				msg.u.create_trace_chunk.credentials.value.uid),
			.gid = LTTNG_OPTIONAL_INIT_VALUE(
				msg.u.create_trace_chunk.credentials.value.gid),
		};
		const bool is_local_trace = !msg.u.create_trace_chunk.relayd_id.is_set;
		const uint64_t relayd_id = msg.u.create_trace_chunk.relayd_id.value;
		const char *chunk_override_name = *msg.u.create_trace_chunk.override_name ?
			msg.u.create_trace_chunk.override_name :
			nullptr;
		struct lttng_directory_handle *chunk_directory_handle = nullptr;

		/*
		 * The session daemon will only provide a chunk directory file
		 * descriptor for local traces.
		 */
		if (is_local_trace) {
			int chunk_dirfd;
			int ret_send_status;
			ssize_t ret_recv;

			/* Acnowledge the reception of the command. */
			ret_send_status = consumer_send_status_msg(sock, LTTCOMM_CONSUMERD_SUCCESS);
			if (ret_send_status < 0) {
				/* Somehow, the session daemon is not responding anymore. */
				goto end_nosignal;
			}

			ret_recv = lttcomm_recv_fds_unix_sock(sock, &chunk_dirfd, 1);
			if (ret_recv != sizeof(chunk_dirfd)) {
				ERR("Failed to receive trace chunk directory file descriptor");
				goto error_fatal;
			}

			DBG("Received trace chunk directory fd (%d)", chunk_dirfd);
			chunk_directory_handle =
				lttng_directory_handle_create_from_dirfd(chunk_dirfd);
			if (!chunk_directory_handle) {
				ERR("Failed to initialize chunk directory handle from directory file descriptor");
				if (close(chunk_dirfd)) {
					PERROR("Failed to close chunk directory file descriptor");
				}
				goto error_fatal;
			}
		}

		ret_code = lttng_consumer_create_trace_chunk(
			!is_local_trace ? &relayd_id : nullptr,
			msg.u.create_trace_chunk.session_id,
			msg.u.create_trace_chunk.chunk_id,
			(time_t) msg.u.create_trace_chunk.creation_timestamp,
			chunk_override_name,
			msg.u.create_trace_chunk.credentials.is_set ? &credentials : nullptr,
			chunk_directory_handle);
		lttng_directory_handle_put(chunk_directory_handle);
		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_CLOSE_TRACE_CHUNK:
	{
		enum lttng_trace_chunk_command_type close_command =
			(lttng_trace_chunk_command_type) msg.u.close_trace_chunk.close_command.value;
		const uint64_t relayd_id = msg.u.close_trace_chunk.relayd_id.value;
		struct lttcomm_consumer_close_trace_chunk_reply reply;
		char path[LTTNG_PATH_MAX];
		ssize_t ret_send;

		ret_code = lttng_consumer_close_trace_chunk(
			msg.u.close_trace_chunk.relayd_id.is_set ? &relayd_id : nullptr,
			msg.u.close_trace_chunk.session_id,
			msg.u.close_trace_chunk.chunk_id,
			(time_t) msg.u.close_trace_chunk.close_timestamp,
			msg.u.close_trace_chunk.close_command.is_set ? &close_command : nullptr,
			path);
		reply.ret_code = ret_code;
		reply.path_length = strlen(path) + 1;
		ret_send = lttcomm_send_unix_sock(sock, &reply, sizeof(reply));
		if (ret_send != sizeof(reply)) {
			goto error_fatal;
		}
		ret_send = lttcomm_send_unix_sock(sock, path, reply.path_length);
		if (ret_send != reply.path_length) {
			goto error_fatal;
		}
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_TRACE_CHUNK_EXISTS:
	{
		const uint64_t relayd_id = msg.u.trace_chunk_exists.relayd_id.value;

		ret_code = lttng_consumer_trace_chunk_exists(
			msg.u.trace_chunk_exists.relayd_id.is_set ? &relayd_id : nullptr,
			msg.u.trace_chunk_exists.session_id,
			msg.u.trace_chunk_exists.chunk_id);
		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_OPEN_CHANNEL_PACKETS:
	{
		const uint64_t key = msg.u.open_channel_packets.key;
		struct lttng_consumer_channel *channel = consumer_find_channel(key);

		if (channel) {
			pthread_mutex_lock(&channel->lock);
			ret_code = lttng_consumer_open_channel_packets(channel);
			pthread_mutex_unlock(&channel->lock);
		} else {
			WARN("Channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		}

		health_code_update();
		goto end_msg_sessiond;
	}
	default:
		goto end_nosignal;
	}

end_nosignal:
	/*
	 * Return 1 to indicate success since the 0 value can be a socket
	 * shutdown during the recv() or send() call.
	 */
	ret_func = 1;
	goto end;
error_fatal:
	/* This will issue a consumer stop. */
	ret_func = -1;
	goto end;
end_msg_sessiond:
	/*
	 * The returned value here is not useful since either way we'll return 1 to
	 * the caller because the session daemon socket management is done
	 * elsewhere. Returning a negative code or 0 will shutdown the consumer.
	 */
	{
		int ret_send_status;

		ret_send_status = consumer_send_status_msg(sock, ret_code);
		if (ret_send_status < 0) {
			goto error_fatal;
		}
	}

	ret_func = 1;

end:
	health_code_update();
	return ret_func;
}

/*
 * Sync metadata meaning request them to the session daemon and snapshot to the
 * metadata thread can consumer them.
 *
 * Metadata stream lock MUST be acquired.
 */
enum sync_metadata_status lttng_kconsumer_sync_metadata(struct lttng_consumer_stream *metadata)
{
	int ret;
	enum sync_metadata_status status;

	LTTNG_ASSERT(metadata);

	ret = kernctl_buffer_flush(metadata->wait_fd);
	if (ret < 0) {
		ERR("Failed to flush kernel stream");
		status = SYNC_METADATA_STATUS_ERROR;
		goto end;
	}

	ret = kernctl_snapshot(metadata->wait_fd);
	if (ret < 0) {
		if (errno == EAGAIN) {
			/* No new metadata, exit. */
			DBG("Sync metadata, no new kernel metadata");
			status = SYNC_METADATA_STATUS_NO_DATA;
		} else {
			ERR("Sync metadata, taking kernel snapshot failed.");
			status = SYNC_METADATA_STATUS_ERROR;
		}
	} else {
		status = SYNC_METADATA_STATUS_NEW_DATA;
	}

end:
	return status;
}

static int extract_common_subbuffer_info(struct lttng_consumer_stream *stream,
					 struct stream_subbuffer *subbuf)
{
	int ret;

	ret = kernctl_get_subbuf_size(stream->wait_fd, &subbuf->info.data.subbuf_size);
	if (ret) {
		goto end;
	}

	ret = kernctl_get_padded_subbuf_size(stream->wait_fd,
					     &subbuf->info.data.padded_subbuf_size);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

static int extract_metadata_subbuffer_info(struct lttng_consumer_stream *stream,
					   struct stream_subbuffer *subbuf)
{
	int ret;

	ret = extract_common_subbuffer_info(stream, subbuf);
	if (ret) {
		goto end;
	}

	ret = kernctl_get_metadata_version(stream->wait_fd, &subbuf->info.metadata.version);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

static int extract_data_subbuffer_info(struct lttng_consumer_stream *stream,
				       struct stream_subbuffer *subbuf)
{
	int ret;

	ret = extract_common_subbuffer_info(stream, subbuf);
	if (ret) {
		goto end;
	}

	ret = kernctl_get_packet_size(stream->wait_fd, &subbuf->info.data.packet_size);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer packet size");
		goto end;
	}

	ret = kernctl_get_content_size(stream->wait_fd, &subbuf->info.data.content_size);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer content size");
		goto end;
	}

	ret = kernctl_get_timestamp_begin(stream->wait_fd, &subbuf->info.data.timestamp_begin);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer begin timestamp");
		goto end;
	}

	ret = kernctl_get_timestamp_end(stream->wait_fd, &subbuf->info.data.timestamp_end);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer end timestamp");
		goto end;
	}

	ret = kernctl_get_events_discarded(stream->wait_fd, &subbuf->info.data.events_discarded);
	if (ret) {
		PERROR("Failed to get sub-buffer events discarded count");
		goto end;
	}

	ret = kernctl_get_sequence_number(stream->wait_fd,
					  &subbuf->info.data.sequence_number.value);
	if (ret) {
		/* May not be supported by older LTTng-modules. */
		if (ret != -ENOTTY) {
			PERROR("Failed to get sub-buffer sequence number");
			goto end;
		}
	} else {
		subbuf->info.data.sequence_number.is_set = true;
	}

	ret = kernctl_get_stream_id(stream->wait_fd, &subbuf->info.data.stream_id);
	if (ret < 0) {
		PERROR("Failed to get stream id");
		goto end;
	}

	ret = kernctl_get_instance_id(stream->wait_fd, &subbuf->info.data.stream_instance_id.value);
	if (ret) {
		/* May not be supported by older LTTng-modules. */
		if (ret != -ENOTTY) {
			PERROR("Failed to get stream instance id");
			goto end;
		}
	} else {
		subbuf->info.data.stream_instance_id.is_set = true;
	}
end:
	return ret;
}

static enum get_next_subbuffer_status get_subbuffer_common(struct lttng_consumer_stream *stream,
							   struct stream_subbuffer *subbuffer)
{
	int ret;
	enum get_next_subbuffer_status status;

	ret = kernctl_get_next_subbuf(stream->wait_fd);
	switch (ret) {
	case 0:
		status = GET_NEXT_SUBBUFFER_STATUS_OK;
		break;
	case -ENODATA:
	case -EAGAIN:
		/*
		 * The caller only expects -ENODATA when there is no data to
		 * read, but the kernel tracer returns -EAGAIN when there is
		 * currently no data for a non-finalized stream, and -ENODATA
		 * when there is no data for a finalized stream. Those can be
		 * combined into a -ENODATA return value.
		 */
		status = GET_NEXT_SUBBUFFER_STATUS_NO_DATA;
		goto end;
	default:
		status = GET_NEXT_SUBBUFFER_STATUS_ERROR;
		goto end;
	}

	ret = stream->read_subbuffer_ops.extract_subbuffer_info(stream, subbuffer);
	if (ret) {
		status = GET_NEXT_SUBBUFFER_STATUS_ERROR;
	}
end:
	return status;
}

static enum get_next_subbuffer_status
get_next_subbuffer_splice(struct lttng_consumer_stream *stream, struct stream_subbuffer *subbuffer)
{
	const enum get_next_subbuffer_status status = get_subbuffer_common(stream, subbuffer);

	if (status != GET_NEXT_SUBBUFFER_STATUS_OK) {
		goto end;
	}

	subbuffer->buffer.fd = stream->wait_fd;
end:
	return status;
}

static enum get_next_subbuffer_status get_next_subbuffer_mmap(struct lttng_consumer_stream *stream,
							      struct stream_subbuffer *subbuffer)
{
	int ret;
	enum get_next_subbuffer_status status;
	const char *addr;

	status = get_subbuffer_common(stream, subbuffer);
	if (status != GET_NEXT_SUBBUFFER_STATUS_OK) {
		goto end;
	}

	ret = get_current_subbuf_addr(stream, &addr);
	if (ret) {
		status = GET_NEXT_SUBBUFFER_STATUS_ERROR;
		goto end;
	}

	subbuffer->buffer.buffer =
		lttng_buffer_view_init(addr, 0, subbuffer->info.data.padded_subbuf_size);
end:
	return status;
}

static enum get_next_subbuffer_status
get_next_subbuffer_metadata_check(struct lttng_consumer_stream *stream,
				  struct stream_subbuffer *subbuffer)
{
	int ret;
	const char *addr;
	bool coherent;
	enum get_next_subbuffer_status status;

	ret = kernctl_get_next_subbuf_metadata_check(stream->wait_fd, &coherent);
	if (ret) {
		goto end;
	}

	ret = stream->read_subbuffer_ops.extract_subbuffer_info(stream, subbuffer);
	if (ret) {
		goto end;
	}

	LTTNG_OPTIONAL_SET(&subbuffer->info.metadata.coherent, coherent);

	ret = get_current_subbuf_addr(stream, &addr);
	if (ret) {
		goto end;
	}

	subbuffer->buffer.buffer =
		lttng_buffer_view_init(addr, 0, subbuffer->info.data.padded_subbuf_size);
	DBG("Got metadata packet with padded_subbuf_size = %lu, coherent = %s",
	    subbuffer->info.metadata.padded_subbuf_size,
	    coherent ? "true" : "false");
end:
	/*
	 * The caller only expects -ENODATA when there is no data to read, but
	 * the kernel tracer returns -EAGAIN when there is currently no data
	 * for a non-finalized stream, and -ENODATA when there is no data for a
	 * finalized stream. Those can be combined into a -ENODATA return value.
	 */
	switch (ret) {
	case 0:
		status = GET_NEXT_SUBBUFFER_STATUS_OK;
		break;
	case -ENODATA:
	case -EAGAIN:
		/*
		 * The caller only expects -ENODATA when there is no data to
		 * read, but the kernel tracer returns -EAGAIN when there is
		 * currently no data for a non-finalized stream, and -ENODATA
		 * when there is no data for a finalized stream. Those can be
		 * combined into a -ENODATA return value.
		 */
		status = GET_NEXT_SUBBUFFER_STATUS_NO_DATA;
		break;
	default:
		status = GET_NEXT_SUBBUFFER_STATUS_ERROR;
		break;
	}

	return status;
}

static int put_next_subbuffer(struct lttng_consumer_stream *stream,
			      struct stream_subbuffer *subbuffer __attribute__((unused)))
{
	const int ret = kernctl_put_next_subbuf(stream->wait_fd);

	if (ret) {
		if (ret == -EFAULT) {
			PERROR("Error in unreserving sub buffer");
		} else if (ret == -EIO) {
			/* Should never happen with newer LTTng versions */
			PERROR("Reader has been pushed by the writer, last sub-buffer corrupted");
		}
	}

	return ret;
}

static bool is_get_next_check_metadata_available(int tracer_fd)
{
	const int ret = kernctl_get_next_subbuf_metadata_check(tracer_fd, nullptr);
	const bool available = ret != -ENOTTY;

	if (ret == 0) {
		/* get succeeded, make sure to put the subbuffer. */
		kernctl_put_subbuf(tracer_fd);
	}

	return available;
}

static int signal_metadata(struct lttng_consumer_stream *stream,
			   struct lttng_consumer_local_data *ctx __attribute__((unused)))
{
	ASSERT_LOCKED(stream->metadata_rdv_lock);
	return pthread_cond_broadcast(&stream->metadata_rdv) ? -errno : 0;
}

static int lttng_kconsumer_set_stream_ops(struct lttng_consumer_stream *stream)
{
	int ret = 0;

	if (stream->metadata_flag && stream->chan->is_live) {
		DBG("Attempting to enable metadata bucketization for live consumers");
		if (is_get_next_check_metadata_available(stream->wait_fd)) {
			DBG("Kernel tracer supports get_next_subbuffer_metadata_check, metadata will be accumulated until a coherent state is reached");
			stream->read_subbuffer_ops.get_next_subbuffer =
				get_next_subbuffer_metadata_check;
			ret = consumer_stream_enable_metadata_bucketization(stream);
			if (ret) {
				goto end;
			}
		} else {
			/*
			 * The kernel tracer version is too old to indicate
			 * when the metadata stream has reached a "coherent"
			 * (parseable) point.
			 *
			 * This means that a live viewer may see an incoherent
			 * sequence of metadata and fail to parse it.
			 */
			WARN("Kernel tracer does not support get_next_subbuffer_metadata_check which may cause live clients to fail to parse the metadata stream");
			metadata_bucket_destroy(stream->metadata_bucket);
			stream->metadata_bucket = nullptr;
		}

		stream->read_subbuffer_ops.on_sleep = signal_metadata;
	}

	if (!stream->read_subbuffer_ops.get_next_subbuffer) {
		if (stream->chan->output == CONSUMER_CHANNEL_MMAP) {
			stream->read_subbuffer_ops.get_next_subbuffer = get_next_subbuffer_mmap;
		} else {
			stream->read_subbuffer_ops.get_next_subbuffer = get_next_subbuffer_splice;
		}
	}

	if (stream->metadata_flag) {
		stream->read_subbuffer_ops.extract_subbuffer_info = extract_metadata_subbuffer_info;
	} else {
		stream->read_subbuffer_ops.extract_subbuffer_info = extract_data_subbuffer_info;
		if (stream->chan->is_live) {
			stream->read_subbuffer_ops.send_live_beacon = consumer_flush_kernel_index;
		}
	}

	stream->read_subbuffer_ops.put_next_subbuffer = put_next_subbuffer;
end:
	return ret;
}

int lttng_kconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	LTTNG_ASSERT(stream);

	/*
	 * Don't create anything if this is set for streaming or if there is
	 * no current trace chunk on the parent channel.
	 */
	if (stream->net_seq_idx == (uint64_t) -1ULL && stream->chan->monitor &&
	    stream->chan->trace_chunk) {
		ret = consumer_stream_create_output_files(stream, true);
		if (ret) {
			goto error;
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

		stream->mmap_base =
			mmap(nullptr, stream->mmap_len, PROT_READ, MAP_PRIVATE, stream->wait_fd, 0);
		if (stream->mmap_base == MAP_FAILED) {
			PERROR("Error mmaping");
			ret = -1;
			goto error_close_fd;
		}
	}

	ret = lttng_kconsumer_set_stream_ops(stream);
	if (ret) {
		goto error_close_fd;
	}

	/* we return 0 to let the library handle the FD internally */
	return 0;

error_close_fd:
	if (stream->out_fd >= 0) {
		int err;

		err = close(stream->out_fd);
		LTTNG_ASSERT(!err);
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

	LTTNG_ASSERT(stream);

	if (stream->endpoint_status != CONSUMER_ENDPOINT_ACTIVE) {
		ret = 0;
		goto end;
	}

	ret = kernctl_get_next_subbuf(stream->wait_fd);
	if (ret == 0) {
		/* There is still data so let's put back this subbuffer. */
		ret = kernctl_put_subbuf(stream->wait_fd);
		LTTNG_ASSERT(ret == 0);
		ret = 1; /* Data is pending */
		goto end;
	}

	/* Data is NOT pending and ready to be read. */
	ret = 0;

end:
	return ret;
}
