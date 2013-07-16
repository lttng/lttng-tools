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
#include <urcu/list.h>
#include <signal.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/relayd/relayd.h>
#include <common/compat/fcntl.h>
#include <common/consumer-metadata-cache.h>
#include <common/consumer-stream.h>
#include <common/consumer-timer.h>
#include <common/utils.h>

#include "ust-consumer.h"

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;
extern volatile int consumer_quit;

/*
 * Free channel object and all streams associated with it. This MUST be used
 * only and only if the channel has _NEVER_ been added to the global channel
 * hash table.
 */
static void destroy_channel(struct lttng_consumer_channel *channel)
{
	struct lttng_consumer_stream *stream, *stmp;

	assert(channel);

	DBG("UST consumer cleaning stream list");

	cds_list_for_each_entry_safe(stream, stmp, &channel->streams.head,
			send_node) {
		cds_list_del(&stream->send_node);
		ustctl_destroy_stream(stream->ustream);
		free(stream);
	}

	/*
	 * If a channel is available meaning that was created before the streams
	 * were, delete it.
	 */
	if (channel->uchan) {
		lttng_ustconsumer_del_channel(channel);
	}
	free(channel);
}

/*
 * Add channel to internal consumer state.
 *
 * Returns 0 on success or else a negative value.
 */
static int add_channel(struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx)
{
	int ret = 0;

	assert(channel);
	assert(ctx);

	if (ctx->on_recv_channel != NULL) {
		ret = ctx->on_recv_channel(channel);
		if (ret == 0) {
			ret = consumer_add_channel(channel, ctx);
		} else if (ret < 0) {
			/* Most likely an ENOMEM. */
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
			goto error;
		}
	} else {
		ret = consumer_add_channel(channel, ctx);
	}

	DBG("UST consumer channel added (key: %" PRIu64 ")", channel->key);

error:
	return ret;
}

/*
 * Allocate and return a consumer channel object.
 */
static struct lttng_consumer_channel *allocate_channel(uint64_t session_id,
		const char *pathname, const char *name, uid_t uid, gid_t gid,
		uint64_t relayd_id, uint64_t key, enum lttng_event_output output,
		uint64_t tracefile_size, uint64_t tracefile_count,
		uint64_t session_id_per_pid, unsigned int monitor)
{
	assert(pathname);
	assert(name);

	return consumer_allocate_channel(key, session_id, pathname, name, uid,
			gid, relayd_id, output, tracefile_size,
			tracefile_count, session_id_per_pid, monitor);
}

/*
 * Allocate and return a consumer stream object. If _alloc_ret is not NULL, the
 * error value if applicable is set in it else it is kept untouched.
 *
 * Return NULL on error else the newly allocated stream object.
 */
static struct lttng_consumer_stream *allocate_stream(int cpu, int key,
		struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx, int *_alloc_ret)
{
	int alloc_ret;
	struct lttng_consumer_stream *stream = NULL;

	assert(channel);
	assert(ctx);

	stream = consumer_allocate_stream(channel->key,
			key,
			LTTNG_CONSUMER_ACTIVE_STREAM,
			channel->name,
			channel->uid,
			channel->gid,
			channel->relayd_id,
			channel->session_id,
			cpu,
			&alloc_ret,
			channel->type,
			channel->monitor);
	if (stream == NULL) {
		switch (alloc_ret) {
		case -ENOENT:
			/*
			 * We could not find the channel. Can happen if cpu hotplug
			 * happens while tearing down.
			 */
			DBG3("Could not find channel");
			break;
		case -ENOMEM:
		case -EINVAL:
		default:
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
			break;
		}
		goto error;
	}

	stream->chan = channel;

error:
	if (_alloc_ret) {
		*_alloc_ret = alloc_ret;
	}
	return stream;
}

/*
 * Send the given stream pointer to the corresponding thread.
 *
 * Returns 0 on success else a negative value.
 */
static int send_stream_to_thread(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	int ret;
	struct lttng_pipe *stream_pipe;

	/* Get the right pipe where the stream will be sent. */
	if (stream->metadata_flag) {
		stream_pipe = ctx->consumer_metadata_pipe;
	} else {
		stream_pipe = ctx->consumer_data_pipe;
	}

	ret = lttng_pipe_write(stream_pipe, &stream, sizeof(stream));
	if (ret < 0) {
		ERR("Consumer write %s stream to pipe %d",
				stream->metadata_flag ? "metadata" : "data",
				lttng_pipe_get_writefd(stream_pipe));
	}

	return ret;
}

/*
 * Create streams for the given channel using liblttng-ust-ctl.
 *
 * Return 0 on success else a negative value.
 */
static int create_ust_streams(struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx)
{
	int ret, cpu = 0;
	struct ustctl_consumer_stream *ustream;
	struct lttng_consumer_stream *stream;

	assert(channel);
	assert(ctx);

	/*
	 * While a stream is available from ustctl. When NULL is returned, we've
	 * reached the end of the possible stream for the channel.
	 */
	while ((ustream = ustctl_create_stream(channel->uchan, cpu))) {
		int wait_fd;

		wait_fd = ustctl_stream_get_wait_fd(ustream);

		/* Allocate consumer stream object. */
		stream = allocate_stream(cpu, wait_fd, channel, ctx, &ret);
		if (!stream) {
			goto error_alloc;
		}
		stream->ustream = ustream;
		/*
		 * Store it so we can save multiple function calls afterwards since
		 * this value is used heavily in the stream threads. This is UST
		 * specific so this is why it's done after allocation.
		 */
		stream->wait_fd = wait_fd;

		/*
		 * Increment channel refcount since the channel reference has now been
		 * assigned in the allocation process above.
		 */
		if (stream->chan->monitor) {
			uatomic_inc(&stream->chan->refcount);
		}

		/*
		 * Order is important this is why a list is used. On error, the caller
		 * should clean this list.
		 */
		cds_list_add_tail(&stream->send_node, &channel->streams.head);

		ret = ustctl_get_max_subbuf_size(stream->ustream,
				&stream->max_sb_size);
		if (ret < 0) {
			ERR("ustctl_get_max_subbuf_size failed for stream %s",
					stream->name);
			goto error;
		}

		/* Do actions once stream has been received. */
		if (ctx->on_recv_stream) {
			ret = ctx->on_recv_stream(stream);
			if (ret < 0) {
				goto error;
			}
		}

		DBG("UST consumer add stream %s (key: %" PRIu64 ") with relayd id %" PRIu64,
				stream->name, stream->key, stream->relayd_stream_id);

		/* Set next CPU stream. */
		channel->streams.count = ++cpu;

		/* Keep stream reference when creating metadata. */
		if (channel->type == CONSUMER_CHANNEL_TYPE_METADATA) {
			channel->metadata_stream = stream;
		}
	}

	return 0;

error:
error_alloc:
	return ret;
}

/*
 * Create an UST channel with the given attributes and send it to the session
 * daemon using the ust ctl API.
 *
 * Return 0 on success or else a negative value.
 */
static int create_ust_channel(struct ustctl_consumer_channel_attr *attr,
		struct ustctl_consumer_channel **chanp)
{
	int ret;
	struct ustctl_consumer_channel *channel;

	assert(attr);
	assert(chanp);

	DBG3("Creating channel to ustctl with attr: [overwrite: %d, "
			"subbuf_size: %" PRIu64 ", num_subbuf: %" PRIu64 ", "
			"switch_timer_interval: %u, read_timer_interval: %u, "
			"output: %d, type: %d", attr->overwrite, attr->subbuf_size,
			attr->num_subbuf, attr->switch_timer_interval,
			attr->read_timer_interval, attr->output, attr->type);

	channel = ustctl_create_channel(attr);
	if (!channel) {
		ret = -1;
		goto error_create;
	}

	*chanp = channel;

	return 0;

error_create:
	return ret;
}

/*
 * Send a single given stream to the session daemon using the sock.
 *
 * Return 0 on success else a negative value.
 */
static int send_sessiond_stream(int sock, struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);
	assert(sock >= 0);

	DBG("UST consumer sending stream %" PRIu64 " to sessiond", stream->key);

	/* Send stream to session daemon. */
	ret = ustctl_send_stream_to_sessiond(sock, stream->ustream);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send channel to sessiond.
 *
 * Return 0 on success or else a negative value.
 */
static int send_sessiond_channel(int sock,
		struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx, int *relayd_error)
{
	int ret, ret_code = LTTNG_OK;
	struct lttng_consumer_stream *stream;

	assert(channel);
	assert(ctx);
	assert(sock >= 0);

	DBG("UST consumer sending channel %s to sessiond", channel->name);

	if (channel->relayd_id != (uint64_t) -1ULL) {
		cds_list_for_each_entry(stream, &channel->streams.head, send_node) {
			/* Try to send the stream to the relayd if one is available. */
			ret = consumer_send_relayd_stream(stream, stream->chan->pathname);
			if (ret < 0) {
				/*
				 * Flag that the relayd was the problem here probably due to a
				 * communicaton error on the socket.
				 */
				if (relayd_error) {
					*relayd_error = 1;
				}
				ret_code = LTTNG_ERR_RELAYD_CONNECT_FAIL;
			}
		}
	}

	/* Inform sessiond that we are about to send channel and streams. */
	ret = consumer_send_status_msg(sock, ret_code);
	if (ret < 0 || ret_code != LTTNG_OK) {
		/*
		 * Either the session daemon is not responding or the relayd died so we
		 * stop now.
		 */
		goto error;
	}

	/* Send channel to sessiond. */
	ret = ustctl_send_channel_to_sessiond(sock, channel->uchan);
	if (ret < 0) {
		goto error;
	}

	ret = ustctl_channel_close_wakeup_fd(channel->uchan);
	if (ret < 0) {
		goto error;
	}

	/* The channel was sent successfully to the sessiond at this point. */
	cds_list_for_each_entry(stream, &channel->streams.head, send_node) {
		/* Send stream to session daemon. */
		ret = send_sessiond_stream(sock, stream);
		if (ret < 0) {
			goto error;
		}
	}

	/* Tell sessiond there is no more stream. */
	ret = ustctl_send_stream_to_sessiond(sock, NULL);
	if (ret < 0) {
		goto error;
	}

	DBG("UST consumer NULL stream sent to sessiond");

	return 0;

error:
	if (ret_code != LTTNG_OK) {
		ret = -1;
	}
	return ret;
}

/*
 * Creates a channel and streams and add the channel it to the channel internal
 * state. The created stream must ONLY be sent once the GET_CHANNEL command is
 * received.
 *
 * Return 0 on success or else, a negative value is returned and the channel
 * MUST be destroyed by consumer_del_channel().
 */
static int ask_channel(struct lttng_consumer_local_data *ctx, int sock,
		struct lttng_consumer_channel *channel,
		struct ustctl_consumer_channel_attr *attr)
{
	int ret;

	assert(ctx);
	assert(channel);
	assert(attr);

	/*
	 * This value is still used by the kernel consumer since for the kernel,
	 * the stream ownership is not IN the consumer so we need to have the
	 * number of left stream that needs to be initialized so we can know when
	 * to delete the channel (see consumer.c).
	 *
	 * As for the user space tracer now, the consumer creates and sends the
	 * stream to the session daemon which only sends them to the application
	 * once every stream of a channel is received making this value useless
	 * because we they will be added to the poll thread before the application
	 * receives them. This ensures that a stream can not hang up during
	 * initilization of a channel.
	 */
	channel->nb_init_stream_left = 0;

	/* The reply msg status is handled in the following call. */
	ret = create_ust_channel(attr, &channel->uchan);
	if (ret < 0) {
		goto end;
	}

	channel->wait_fd = ustctl_channel_get_wait_fd(channel->uchan);

	/*
	 * For the snapshots (no monitor), we create the metadata streams
	 * on demand, not during the channel creation.
	 */
	if (channel->type == CONSUMER_CHANNEL_TYPE_METADATA && !channel->monitor) {
		ret = 0;
		goto end;
	}

	/* Open all streams for this channel. */
	ret = create_ust_streams(channel, ctx);
	if (ret < 0) {
		goto end;
	}

end:
	return ret;
}

/*
 * Send all stream of a channel to the right thread handling it.
 *
 * On error, return a negative value else 0 on success.
 */
static int send_streams_to_thread(struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx)
{
	int ret = 0;
	struct lttng_consumer_stream *stream, *stmp;

	assert(channel);
	assert(ctx);

	/* Send streams to the corresponding thread. */
	cds_list_for_each_entry_safe(stream, stmp, &channel->streams.head,
			send_node) {
		/* Sending the stream to the thread. */
		ret = send_stream_to_thread(stream, ctx);
		if (ret < 0) {
			/*
			 * If we are unable to send the stream to the thread, there is
			 * a big problem so just stop everything.
			 */
			goto error;
		}

		/* Remove node from the channel stream list. */
		cds_list_del(&stream->send_node);

		/*
		 * From this point on, the stream's ownership has been moved away from
		 * the channel and becomes globally visible.
		 */
		stream->globally_visible = 1;
	}

error:
	return ret;
}

/*
 * Write metadata to the given channel using ustctl to convert the string to
 * the ringbuffer.
 * Called only from consumer_metadata_cache_write.
 * The metadata cache lock MUST be acquired to write in the cache.
 *
 * Return 0 on success else a negative value.
 */
int lttng_ustconsumer_push_metadata(struct lttng_consumer_channel *metadata,
		const char *metadata_str, uint64_t target_offset, uint64_t len)
{
	int ret;

	assert(metadata);
	assert(metadata_str);

	DBG("UST consumer writing metadata to channel %s", metadata->name);

	if (!metadata->metadata_stream) {
		ret = 0;
		goto error;
	}

	assert(target_offset <= metadata->metadata_cache->max_offset);
	ret = ustctl_write_metadata_to_channel(metadata->uchan,
			metadata_str + target_offset, len);
	if (ret < 0) {
		ERR("ustctl write metadata fail with ret %d, len %" PRIu64, ret, len);
		goto error;
	}

	ustctl_flush_buffer(metadata->metadata_stream->ustream, 1);

error:
	return ret;
}

/*
 * Flush channel's streams using the given key to retrieve the channel.
 *
 * Return 0 on success else an LTTng error code.
 */
static int flush_channel(uint64_t chan_key)
{
	int ret = 0;
	struct lttng_consumer_channel *channel;
	struct lttng_consumer_stream *stream;
	struct lttng_ht *ht;
	struct lttng_ht_iter iter;

	DBG("UST consumer flush channel key %" PRIu64, chan_key);

	rcu_read_lock();
	channel = consumer_find_channel(chan_key);
	if (!channel) {
		ERR("UST consumer flush channel %" PRIu64 " not found", chan_key);
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto error;
	}

	ht = consumer_data.stream_per_chan_id_ht;

	/* For each stream of the channel id, flush it. */
	cds_lfht_for_each_entry_duplicate(ht->ht,
			ht->hash_fct(&channel->key, lttng_ht_seed), ht->match_fct,
			&channel->key, &iter.iter, stream, node_channel_id.node) {
			ustctl_flush_buffer(stream->ustream, 1);
	}
error:
	rcu_read_unlock();
	return ret;
}

/*
 * Close metadata stream wakeup_fd using the given key to retrieve the channel.
 * RCU read side lock MUST be acquired before calling this function.
 *
 * Return 0 on success else an LTTng error code.
 */
static int close_metadata(uint64_t chan_key)
{
	int ret = 0;
	struct lttng_consumer_channel *channel;

	DBG("UST consumer close metadata key %" PRIu64, chan_key);

	channel = consumer_find_channel(chan_key);
	if (!channel) {
		/*
		 * This is possible if the metadata thread has issue a delete because
		 * the endpoint point of the stream hung up. There is no way the
		 * session daemon can know about it thus use a DBG instead of an actual
		 * error.
		 */
		DBG("UST consumer close metadata %" PRIu64 " not found", chan_key);
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto error;
	}

	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&channel->lock);

	if (cds_lfht_is_node_deleted(&channel->node.node)) {
		goto error_unlock;
	}

	if (channel->switch_timer_enabled == 1) {
		DBG("Deleting timer on metadata channel");
		consumer_timer_switch_stop(channel);
	}

	if (channel->metadata_stream) {
		ret = ustctl_stream_close_wakeup_fd(channel->metadata_stream->ustream);
		if (ret < 0) {
			ERR("UST consumer unable to close fd of metadata (ret: %d)", ret);
			ret = LTTCOMM_CONSUMERD_ERROR_METADATA;
			goto error_unlock;
		}
	}

error_unlock:
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&consumer_data.lock);
error:
	return ret;
}

/*
 * RCU read side lock MUST be acquired before calling this function.
 *
 * Return 0 on success else an LTTng error code.
 */
static int setup_metadata(struct lttng_consumer_local_data *ctx, uint64_t key)
{
	int ret;
	struct lttng_consumer_channel *metadata;

	DBG("UST consumer setup metadata key %" PRIu64, key);

	metadata = consumer_find_channel(key);
	if (!metadata) {
		ERR("UST consumer push metadata %" PRIu64 " not found", key);
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto end;
	}

	/*
	 * In no monitor mode, the metadata channel has no stream(s) so skip the
	 * ownership transfer to the metadata thread.
	 */
	if (!metadata->monitor) {
		DBG("Metadata channel in no monitor");
		ret = 0;
		goto end;
	}

	/*
	 * Send metadata stream to relayd if one available. Availability is
	 * known if the stream is still in the list of the channel.
	 */
	if (cds_list_empty(&metadata->streams.head)) {
		ERR("Metadata channel key %" PRIu64 ", no stream available.", key);
		ret = LTTCOMM_CONSUMERD_ERROR_METADATA;
		goto error_no_stream;
	}

	/* Send metadata stream to relayd if needed. */
	if (metadata->metadata_stream->net_seq_idx != (uint64_t) -1ULL) {
		ret = consumer_send_relayd_stream(metadata->metadata_stream,
				metadata->pathname);
		if (ret < 0) {
			ret = LTTCOMM_CONSUMERD_ERROR_METADATA;
			goto error;
		}
	}

	ret = send_streams_to_thread(metadata, ctx);
	if (ret < 0) {
		/*
		 * If we are unable to send the stream to the thread, there is
		 * a big problem so just stop everything.
		 */
		ret = LTTCOMM_CONSUMERD_FATAL;
		goto error;
	}
	/* List MUST be empty after or else it could be reused. */
	assert(cds_list_empty(&metadata->streams.head));

	ret = 0;
	goto end;

error:
	/*
	 * Delete metadata channel on error. At this point, the metadata stream can
	 * NOT be monitored by the metadata thread thus having the guarantee that
	 * the stream is still in the local stream list of the channel. This call
	 * will make sure to clean that list.
	 */
	cds_list_del(&metadata->metadata_stream->send_node);
	consumer_stream_destroy(metadata->metadata_stream, NULL);
error_no_stream:
end:
	return ret;
}

/*
 * Snapshot the whole metadata.
 *
 * Returns 0 on success, < 0 on error
 */
static int snapshot_metadata(uint64_t key, char *path, uint64_t relayd_id,
		struct lttng_consumer_local_data *ctx)
{
	int ret = 0;
	ssize_t write_len;
	uint64_t total_len = 0;
	struct lttng_consumer_channel *metadata_channel;
	struct lttng_consumer_stream *metadata_stream;

	assert(path);
	assert(ctx);

	DBG("UST consumer snapshot metadata with key %" PRIu64 " at path %s",
			key, path);

	rcu_read_lock();

	metadata_channel = consumer_find_channel(key);
	if (!metadata_channel) {
		ERR("UST snapshot metadata channel not found for key %lu", key);
		ret = -1;
		goto error;
	}
	assert(!metadata_channel->monitor);

	/*
	 * Ask the sessiond if we have new metadata waiting and update the
	 * consumer metadata cache.
	 */
	ret = lttng_ustconsumer_request_metadata(ctx, metadata_channel);
	if (ret < 0) {
		goto error;
	}

	/*
	 * The metadata stream is NOT created in no monitor mode when the channel
	 * is created on a sessiond ask channel command.
	 */
	ret = create_ust_streams(metadata_channel, ctx);
	if (ret < 0) {
		goto error;
	}

	metadata_stream = metadata_channel->metadata_stream;
	assert(metadata_stream);

	if (relayd_id != (uint64_t) -1ULL) {
		metadata_stream->net_seq_idx = relayd_id;
		ret = consumer_send_relayd_stream(metadata_stream, path);
		if (ret < 0) {
			goto error_stream;
		}
	} else {
		ret = utils_create_stream_file(path, metadata_stream->name,
				metadata_stream->chan->tracefile_size,
				metadata_stream->tracefile_count_current,
				metadata_stream->uid, metadata_stream->gid);
		if (ret < 0) {
			goto error_stream;
		}
		metadata_stream->out_fd = ret;
		metadata_stream->tracefile_size_current = 0;
	}

	pthread_mutex_lock(&metadata_channel->metadata_cache->lock);
	while (total_len < metadata_channel->metadata_cache->total_bytes_written) {
		/*
		 * Write at most one packet of metadata into the channel
		 * to avoid blocking here.
		 */
		write_len = ustctl_write_one_packet_to_channel(metadata_channel->uchan,
				metadata_channel->metadata_cache->data,
				metadata_channel->metadata_cache->total_bytes_written);
		if (write_len < 0) {
			ERR("UST consumer snapshot writing metadata packet");
			ret = -1;
			goto error_unlock;
		}
		total_len += write_len;

		DBG("Written %" PRIu64 " bytes to metadata (left: %" PRIu64 ")",
				write_len,
				metadata_channel->metadata_cache->total_bytes_written - write_len);
		ustctl_flush_buffer(metadata_stream->ustream, 1);
		ret = lttng_consumer_read_subbuffer(metadata_stream, ctx);
		if (ret < 0) {
			goto error_unlock;
		}
	}

error_unlock:
	pthread_mutex_unlock(&metadata_channel->metadata_cache->lock);

error_stream:
	/*
	 * Clean up the stream completly because the next snapshot will use a new
	 * metadata stream.
	 */
	cds_list_del(&metadata_stream->send_node);
	consumer_stream_destroy(metadata_stream, NULL);
	metadata_channel->metadata_stream = NULL;

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Take a snapshot of all the stream of a channel.
 *
 * Returns 0 on success, < 0 on error
 */
static int snapshot_channel(uint64_t key, char *path, uint64_t relayd_id,
		uint64_t max_stream_size, struct lttng_consumer_local_data *ctx)
{
	int ret;
	unsigned use_relayd = 0;
	unsigned long consumed_pos, produced_pos;
	struct lttng_consumer_channel *channel;
	struct lttng_consumer_stream *stream;

	assert(path);
	assert(ctx);

	rcu_read_lock();

	if (relayd_id != (uint64_t) -1ULL) {
		use_relayd = 1;
	}

	channel = consumer_find_channel(key);
	if (!channel) {
		ERR("UST snapshot channel not found for key %lu", key);
		ret = -1;
		goto error;
	}
	assert(!channel->monitor);
	DBG("UST consumer snapshot channel %lu", key);

	cds_list_for_each_entry(stream, &channel->streams.head, send_node) {
		/* Lock stream because we are about to change its state. */
		pthread_mutex_lock(&stream->lock);
		stream->net_seq_idx = relayd_id;

		if (use_relayd) {
			ret = consumer_send_relayd_stream(stream, path);
			if (ret < 0) {
				goto error_unlock;
			}
		} else {
			ret = utils_create_stream_file(path, stream->name,
					stream->chan->tracefile_size,
					stream->tracefile_count_current,
					stream->uid, stream->gid);
			if (ret < 0) {
				goto error_unlock;
			}
			stream->out_fd = ret;
			stream->tracefile_size_current = 0;

			DBG("UST consumer snapshot stream %s/%s (%" PRIu64 ")", path,
					stream->name, stream->key);
		}

		ustctl_flush_buffer(stream->ustream, 1);

		ret = lttng_ustconsumer_take_snapshot(stream);
		if (ret < 0) {
			ERR("Taking UST snapshot");
			goto error_unlock;
		}

		ret = lttng_ustconsumer_get_produced_snapshot(stream, &produced_pos);
		if (ret < 0) {
			ERR("Produced UST snapshot position");
			goto error_unlock;
		}

		ret = lttng_ustconsumer_get_consumed_snapshot(stream, &consumed_pos);
		if (ret < 0) {
			ERR("Consumerd UST snapshot position");
			goto error_unlock;
		}

		/*
		 * The original value is sent back if max stream size is larger than
		 * the possible size of the snapshot. Also, we asume that the session
		 * daemon should never send a maximum stream size that is lower than
		 * subbuffer size.
		 */
		consumed_pos = consumer_get_consumed_maxsize(consumed_pos,
				produced_pos, max_stream_size);

		while (consumed_pos < produced_pos) {
			ssize_t read_len;
			unsigned long len, padded_len;

			DBG("UST consumer taking snapshot at pos %lu", consumed_pos);

			ret = ustctl_get_subbuf(stream->ustream, &consumed_pos);
			if (ret < 0) {
				if (ret != -EAGAIN) {
					PERROR("ustctl_get_subbuf snapshot");
					goto error_close_stream;
				}
				DBG("UST consumer get subbuf failed. Skipping it.");
				consumed_pos += stream->max_sb_size;
				continue;
			}

			ret = ustctl_get_subbuf_size(stream->ustream, &len);
			if (ret < 0) {
				ERR("Snapshot ustctl_get_subbuf_size");
				goto error_put_subbuf;
			}

			ret = ustctl_get_padded_subbuf_size(stream->ustream, &padded_len);
			if (ret < 0) {
				ERR("Snapshot ustctl_get_padded_subbuf_size");
				goto error_put_subbuf;
			}

			read_len = lttng_consumer_on_read_subbuffer_mmap(ctx, stream, len,
					padded_len - len);
			if (use_relayd) {
				if (read_len != len) {
					ret = -1;
					goto error_put_subbuf;
				}
			} else {
				if (read_len != padded_len) {
					ret = -1;
					goto error_put_subbuf;
				}
			}

			ret = ustctl_put_subbuf(stream->ustream);
			if (ret < 0) {
				ERR("Snapshot ustctl_put_subbuf");
				goto error_close_stream;
			}
			consumed_pos += stream->max_sb_size;
		}

		/* Simply close the stream so we can use it on the next snapshot. */
		consumer_stream_close(stream);
		pthread_mutex_unlock(&stream->lock);
	}

	rcu_read_unlock();
	return 0;

error_put_subbuf:
	if (ustctl_put_subbuf(stream->ustream) < 0) {
		ERR("Snapshot ustctl_put_subbuf");
	}
error_close_stream:
	consumer_stream_close(stream);
error_unlock:
	pthread_mutex_unlock(&stream->lock);
error:
	rcu_read_unlock();
	return ret;
}

/*
 * Receive the metadata updates from the sessiond.
 */
int lttng_ustconsumer_recv_metadata(int sock, uint64_t key, uint64_t offset,
		uint64_t len, struct lttng_consumer_channel *channel)
{
	int ret, ret_code = LTTNG_OK;
	char *metadata_str;

	DBG("UST consumer push metadata key %" PRIu64 " of len %" PRIu64, key, len);

	metadata_str = zmalloc(len * sizeof(char));
	if (!metadata_str) {
		PERROR("zmalloc metadata string");
		ret_code = LTTCOMM_CONSUMERD_ENOMEM;
		goto end;
	}

	/* Receive metadata string. */
	ret = lttcomm_recv_unix_sock(sock, metadata_str, len);
	if (ret < 0) {
		/* Session daemon is dead so return gracefully. */
		ret_code = ret;
		goto end_free;
	}

	/*
	 * XXX: The consumer data lock is acquired before calling metadata cache
	 * write which calls push metadata that MUST be protected by the consumer
	 * lock in order to be able to check the validity of the metadata stream of
	 * the channel.
	 *
	 * Note that this will be subject to change to better fine grained locking
	 * and ultimately try to get rid of this global consumer data lock.
	 */
	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&channel->lock);
	pthread_mutex_lock(&channel->metadata_cache->lock);
	ret = consumer_metadata_cache_write(channel, offset, len, metadata_str);
	if (ret < 0) {
		/* Unable to handle metadata. Notify session daemon. */
		ret_code = LTTCOMM_CONSUMERD_ERROR_METADATA;
		/*
		 * Skip metadata flush on write error since the offset and len might
		 * not have been updated which could create an infinite loop below when
		 * waiting for the metadata cache to be flushed.
		 */
		pthread_mutex_unlock(&channel->metadata_cache->lock);
		pthread_mutex_unlock(&channel->lock);
		pthread_mutex_unlock(&consumer_data.lock);
		goto end_free;
	}
	pthread_mutex_unlock(&channel->metadata_cache->lock);
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&consumer_data.lock);

	while (consumer_metadata_cache_flushed(channel, offset + len)) {
		DBG("Waiting for metadata to be flushed");
		usleep(DEFAULT_METADATA_AVAILABILITY_WAIT_TIME);
	}

end_free:
	free(metadata_str);
end:
	return ret_code;
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
	enum lttng_error_code ret_code = LTTNG_OK;
	struct lttcomm_consumer_msg msg;
	struct lttng_consumer_channel *channel = NULL;

	ret = lttcomm_recv_unix_sock(sock, &msg, sizeof(msg));
	if (ret != sizeof(msg)) {
		DBG("Consumer received unexpected message size %zd (expects %zu)",
			ret, sizeof(msg));
		/*
		 * The ret value might 0 meaning an orderly shutdown but this is ok
		 * since the caller handles this.
		 */
		if (ret > 0) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_CMD);
			ret = -1;
		}
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

	/* relayd needs RCU read-side lock */
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
	case LTTNG_CONSUMER_DESTROY_RELAYD:
	{
		uint64_t index = msg.u.destroy_relayd.net_seq_idx;
		struct consumer_relayd_sock_pair *relayd;

		DBG("UST consumer destroying relayd %" PRIu64, index);

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

		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_UPDATE_STREAM:
	{
		rcu_read_unlock();
		return -ENOSYS;
	}
	case LTTNG_CONSUMER_DATA_PENDING:
	{
		int ret, is_data_pending;
		uint64_t id = msg.u.data_pending.session_id;

		DBG("UST consumer data pending command for id %" PRIu64, id);

		is_data_pending = consumer_data_pending(id);

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &is_data_pending,
				sizeof(is_data_pending));
		if (ret < 0) {
			DBG("Error when sending the data pending ret code: %d", ret);
			goto error_fatal;
		}

		/*
		 * No need to send back a status message since the data pending
		 * returned value is the response.
		 */
		break;
	}
	case LTTNG_CONSUMER_ASK_CHANNEL_CREATION:
	{
		int ret;
		struct ustctl_consumer_channel_attr attr;

		/* Create a plain object and reserve a channel key. */
		channel = allocate_channel(msg.u.ask_channel.session_id,
				msg.u.ask_channel.pathname, msg.u.ask_channel.name,
				msg.u.ask_channel.uid, msg.u.ask_channel.gid,
				msg.u.ask_channel.relayd_id, msg.u.ask_channel.key,
				(enum lttng_event_output) msg.u.ask_channel.output,
				msg.u.ask_channel.tracefile_size,
				msg.u.ask_channel.tracefile_count,
				msg.u.ask_channel.session_id_per_pid,
				msg.u.ask_channel.monitor);
		if (!channel) {
			goto end_channel_error;
		}

		/* Build channel attributes from received message. */
		attr.subbuf_size = msg.u.ask_channel.subbuf_size;
		attr.num_subbuf = msg.u.ask_channel.num_subbuf;
		attr.overwrite = msg.u.ask_channel.overwrite;
		attr.switch_timer_interval = msg.u.ask_channel.switch_timer_interval;
		attr.read_timer_interval = msg.u.ask_channel.read_timer_interval;
		attr.chan_id = msg.u.ask_channel.chan_id;
		attr.output = msg.u.ask_channel.output;
		memcpy(attr.uuid, msg.u.ask_channel.uuid, sizeof(attr.uuid));

		/* Translate and save channel type. */
		switch (msg.u.ask_channel.type) {
		case LTTNG_UST_CHAN_PER_CPU:
			channel->type = CONSUMER_CHANNEL_TYPE_DATA;
			attr.type = LTTNG_UST_CHAN_PER_CPU;
			/*
			 * Set refcount to 1 for owner. Below, we will
			 * pass ownership to the
			 * consumer_thread_channel_poll() thread.
			 */
			channel->refcount = 1;
			break;
		case LTTNG_UST_CHAN_METADATA:
			channel->type = CONSUMER_CHANNEL_TYPE_METADATA;
			attr.type = LTTNG_UST_CHAN_METADATA;
			break;
		default:
			assert(0);
			goto error_fatal;
		};

		ret = ask_channel(ctx, sock, channel, &attr);
		if (ret < 0) {
			goto end_channel_error;
		}

		if (msg.u.ask_channel.type == LTTNG_UST_CHAN_METADATA) {
			ret = consumer_metadata_cache_allocate(channel);
			if (ret < 0) {
				ERR("Allocating metadata cache");
				goto end_channel_error;
			}
			consumer_timer_switch_start(channel, attr.switch_timer_interval);
			attr.switch_timer_interval = 0;
		}

		/*
		 * Add the channel to the internal state AFTER all streams were created
		 * and successfully sent to session daemon. This way, all streams must
		 * be ready before this channel is visible to the threads.
		 * If add_channel succeeds, ownership of the channel is
		 * passed to consumer_thread_channel_poll().
		 */
		ret = add_channel(channel, ctx);
		if (ret < 0) {
			if (msg.u.ask_channel.type == LTTNG_UST_CHAN_METADATA) {
				if (channel->switch_timer_enabled == 1) {
					consumer_timer_switch_stop(channel);
				}
				consumer_metadata_cache_destroy(channel);
			}
			goto end_channel_error;
		}

		/*
		 * Channel and streams are now created. Inform the session daemon that
		 * everything went well and should wait to receive the channel and
		 * streams with ustctl API.
		 */
		ret = consumer_send_status_channel(sock, channel);
		if (ret < 0) {
			/*
			 * There is probably a problem on the socket.
			 */
			goto error_fatal;
		}

		break;
	}
	case LTTNG_CONSUMER_GET_CHANNEL:
	{
		int ret, relayd_err = 0;
		uint64_t key = msg.u.get_channel.key;
		struct lttng_consumer_channel *channel;

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("UST consumer get channel key %" PRIu64 " not found", key);
			ret_code = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto end_msg_sessiond;
		}

		/* Send everything to sessiond. */
		ret = send_sessiond_channel(sock, channel, ctx, &relayd_err);
		if (ret < 0) {
			if (relayd_err) {
				/*
				 * We were unable to send to the relayd the stream so avoid
				 * sending back a fatal error to the thread since this is OK
				 * and the consumer can continue its work. The above call
				 * has sent the error status message to the sessiond.
				 */
				goto end_nosignal;
			}
			/*
			 * The communicaton was broken hence there is a bad state between
			 * the consumer and sessiond so stop everything.
			 */
			goto error_fatal;
		}

		/*
		 * In no monitor mode, the streams ownership is kept inside the channel
		 * so don't send them to the data thread.
		 */
		if (!channel->monitor) {
			goto end_msg_sessiond;
		}

		ret = send_streams_to_thread(channel, ctx);
		if (ret < 0) {
			/*
			 * If we are unable to send the stream to the thread, there is
			 * a big problem so just stop everything.
			 */
			goto error_fatal;
		}
		/* List MUST be empty after or else it could be reused. */
		assert(cds_list_empty(&channel->streams.head));
		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_DESTROY_CHANNEL:
	{
		uint64_t key = msg.u.destroy_channel.key;

		/*
		 * Only called if streams have not been sent to stream
		 * manager thread. However, channel has been sent to
		 * channel manager thread.
		 */
		notify_thread_del_channel(ctx, key);
		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_CLOSE_METADATA:
	{
		int ret;

		ret = close_metadata(msg.u.close_metadata.key);
		if (ret != 0) {
			ret_code = ret;
		}

		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_FLUSH_CHANNEL:
	{
		int ret;

		ret = flush_channel(msg.u.flush_channel.key);
		if (ret != 0) {
			ret_code = ret;
		}

		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_PUSH_METADATA:
	{
		int ret;
		uint64_t len = msg.u.push_metadata.len;
		uint64_t key = msg.u.push_metadata.key;
		uint64_t offset = msg.u.push_metadata.target_offset;
		struct lttng_consumer_channel *channel;

		DBG("UST consumer push metadata key %" PRIu64 " of len %" PRIu64, key,
				len);

		channel = consumer_find_channel(key);
		if (!channel) {
			ERR("UST consumer push metadata %" PRIu64 " not found", key);
			ret_code = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto end_msg_sessiond;
		}

		/* Tell session daemon we are ready to receive the metadata. */
		ret = consumer_send_status_msg(sock, LTTNG_OK);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_fatal;
		}

		/* Wait for more data. */
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			goto error_fatal;
		}

		ret = lttng_ustconsumer_recv_metadata(sock, key, offset,
				len, channel);
		if (ret < 0) {
			/* error receiving from sessiond */
			goto error_fatal;
		} else {
			ret_code = ret;
			goto end_msg_sessiond;
		}
	}
	case LTTNG_CONSUMER_SETUP_METADATA:
	{
		int ret;

		ret = setup_metadata(ctx, msg.u.setup_metadata.key);
		if (ret) {
			ret_code = ret;
		}
		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_SNAPSHOT_CHANNEL:
	{
		if (msg.u.snapshot_channel.metadata) {
			ret = snapshot_metadata(msg.u.snapshot_channel.key,
					msg.u.snapshot_channel.pathname,
					msg.u.snapshot_channel.relayd_id,
					ctx);
			if (ret < 0) {
				ERR("Snapshot metadata failed");
				ret_code = LTTNG_ERR_UST_META_FAIL;
			}
		} else {
			ret = snapshot_channel(msg.u.snapshot_channel.key,
					msg.u.snapshot_channel.pathname,
					msg.u.snapshot_channel.relayd_id,
					msg.u.snapshot_channel.max_stream_size,
					ctx);
			if (ret < 0) {
				ERR("Snapshot channel failed");
				ret_code = LTTNG_ERR_UST_CHAN_FAIL;
			}
		}

		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
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

end_msg_sessiond:
	/*
	 * The returned value here is not useful since either way we'll return 1 to
	 * the caller because the session daemon socket management is done
	 * elsewhere. Returning a negative code or 0 will shutdown the consumer.
	 */
	ret = consumer_send_status_msg(sock, ret_code);
	if (ret < 0) {
		goto error_fatal;
	}
	rcu_read_unlock();
	return 1;
end_channel_error:
	if (channel) {
		/*
		 * Free channel here since no one has a reference to it. We don't
		 * free after that because a stream can store this pointer.
		 */
		destroy_channel(channel);
	}
	/* We have to send a status channel message indicating an error. */
	ret = consumer_send_status_channel(sock, NULL);
	if (ret < 0) {
		/* Stop everything if session daemon can not be notified. */
		goto error_fatal;
	}
	rcu_read_unlock();
	return 1;
error_fatal:
	rcu_read_unlock();
	/* This will issue a consumer stop. */
	return -1;
}

/*
 * Wrapper over the mmap() read offset from ust-ctl library. Since this can be
 * compiled out, we isolate it in this library.
 */
int lttng_ustctl_get_mmap_read_offset(struct lttng_consumer_stream *stream,
		unsigned long *off)
{
	assert(stream);
	assert(stream->ustream);

	return ustctl_get_mmap_read_offset(stream->ustream, off);
}

/*
 * Wrapper over the mmap() read offset from ust-ctl library. Since this can be
 * compiled out, we isolate it in this library.
 */
void *lttng_ustctl_get_mmap_base(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	return ustctl_get_mmap_base(stream->ustream);
}

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_ustconsumer_take_snapshot(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	return ustctl_snapshot(stream->ustream);
}

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_ustconsumer_get_produced_snapshot(
		struct lttng_consumer_stream *stream, unsigned long *pos)
{
	assert(stream);
	assert(stream->ustream);
	assert(pos);

	return ustctl_snapshot_get_produced(stream->ustream, pos);
}

/*
 * Get the consumed position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_ustconsumer_get_consumed_snapshot(
		struct lttng_consumer_stream *stream, unsigned long *pos)
{
	assert(stream);
	assert(stream->ustream);
	assert(pos);

	return ustctl_snapshot_get_consumed(stream->ustream, pos);
}

/*
 * Called when the stream signal the consumer that it has hang up.
 */
void lttng_ustconsumer_on_stream_hangup(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	ustctl_flush_buffer(stream->ustream, 0);
	stream->hangup_flush_done = 1;
}

void lttng_ustconsumer_del_channel(struct lttng_consumer_channel *chan)
{
	assert(chan);
	assert(chan->uchan);

	if (chan->switch_timer_enabled == 1) {
		consumer_timer_switch_stop(chan);
	}
	consumer_metadata_cache_destroy(chan);
	ustctl_destroy_channel(chan->uchan);
}

void lttng_ustconsumer_del_stream(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	if (stream->chan->switch_timer_enabled == 1) {
		consumer_timer_switch_stop(stream->chan);
	}
	ustctl_destroy_stream(stream->ustream);
}

int lttng_ustconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	unsigned long len, subbuf_size, padding;
	int err;
	long ret = 0;
	char dummy;
	struct ustctl_consumer_stream *ustream;

	assert(stream);
	assert(stream->ustream);
	assert(ctx);

	DBG("In UST read_subbuffer (wait_fd: %d, name: %s)", stream->wait_fd,
			stream->name);

	/* Ease our life for what's next. */
	ustream = stream->ustream;

	/* We can consume the 1 byte written into the wait_fd by UST */
	if (!stream->hangup_flush_done) {
		ssize_t readlen;

		do {
			readlen = read(stream->wait_fd, &dummy, 1);
		} while (readlen == -1 && errno == EINTR);
		if (readlen == -1) {
			ret = readlen;
			goto end;
		}
	}

	/* Get the next subbuffer */
	err = ustctl_get_next_subbuf(ustream);
	if (err != 0) {
		ret = err;	/* ustctl_get_next_subbuf returns negative, caller expect positive. */
		/*
		 * This is a debug message even for single-threaded consumer,
		 * because poll() have more relaxed criterions than get subbuf,
		 * so get_subbuf may fail for short race windows where poll()
		 * would issue wakeups.
		 */
		DBG("Reserving sub buffer failed (everything is normal, "
				"it is due to concurrency) [ret: %d]", err);
		goto end;
	}
	assert(stream->chan->output == CONSUMER_CHANNEL_MMAP);
	/* Get the full padded subbuffer size */
	err = ustctl_get_padded_subbuf_size(ustream, &len);
	assert(err == 0);

	/* Get subbuffer data size (without padding) */
	err = ustctl_get_subbuf_size(ustream, &subbuf_size);
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
	if ((ret != subbuf_size && stream->net_seq_idx != (uint64_t) -1ULL) ||
			(ret != len && stream->net_seq_idx == (uint64_t) -1ULL)) {
		/*
		 * Display the error but continue processing to try to release the
		 * subbuffer. This is a DBG statement since any unexpected kill or
		 * signal, the application gets unregistered, relayd gets closed or
		 * anything that affects the buffer lifetime will trigger this error.
		 * So, for the sake of the user, don't print this error since it can
		 * happen and it is OK with the code flow.
		 */
		DBG("Error writing to tracefile "
				"(ret: %ld != len: %lu != subbuf_size: %lu)",
				ret, len, subbuf_size);
	}
	err = ustctl_put_next_subbuf(ustream);
	assert(err == 0);

end:
	return ret;
}

/*
 * Called when a stream is created.
 *
 * Return 0 on success or else a negative value.
 */
int lttng_ustconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);

	/* Don't create anything if this is set for streaming. */
	if (stream->net_seq_idx == (uint64_t) -1ULL && stream->chan->monitor) {
		ret = utils_create_stream_file(stream->chan->pathname, stream->name,
				stream->chan->tracefile_size, stream->tracefile_count_current,
				stream->uid, stream->gid);
		if (ret < 0) {
			goto error;
		}
		stream->out_fd = ret;
		stream->tracefile_size_current = 0;
	}
	ret = 0;

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
int lttng_ustconsumer_data_pending(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);
	assert(stream->ustream);

	DBG("UST consumer checking data pending");

	if (stream->endpoint_status != CONSUMER_ENDPOINT_ACTIVE) {
		ret = 0;
		goto end;
	}

	ret = ustctl_get_next_subbuf(stream->ustream);
	if (ret == 0) {
		/* There is still data so let's put back this subbuffer. */
		ret = ustctl_put_subbuf(stream->ustream);
		assert(ret == 0);
		ret = 1;  /* Data is pending */
		goto end;
	}

	/* Data is NOT pending so ready to be read. */
	ret = 0;

end:
	return ret;
}

/*
 * Close every metadata stream wait fd of the metadata hash table. This
 * function MUST be used very carefully so not to run into a race between the
 * metadata thread handling streams and this function closing their wait fd.
 *
 * For UST, this is used when the session daemon hangs up. Its the metadata
 * producer so calling this is safe because we are assured that no state change
 * can occur in the metadata thread for the streams in the hash table.
 */
void lttng_ustconsumer_close_metadata(struct lttng_ht *metadata_ht)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	assert(metadata_ht);
	assert(metadata_ht->ht);

	DBG("UST consumer closing all metadata streams");

	rcu_read_lock();
	cds_lfht_for_each_entry(metadata_ht->ht, &iter.iter, stream,
			node.node) {
		int fd = stream->wait_fd;

		/*
		 * Whatever happens here we have to continue to try to close every
		 * streams. Let's report at least the error on failure.
		 */
		ret = ustctl_stream_close_wakeup_fd(stream->ustream);
		if (ret) {
			ERR("Unable to close metadata stream fd %d ret %d", fd, ret);
		}
		DBG("Metadata wait fd %d closed", fd);
	}
	rcu_read_unlock();
}

void lttng_ustconsumer_close_stream_wakeup(struct lttng_consumer_stream *stream)
{
	int ret;

	ret = ustctl_stream_close_wakeup_fd(stream->ustream);
	if (ret < 0) {
		ERR("Unable to close wakeup fd");
	}
}

int lttng_ustconsumer_request_metadata(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_channel *channel)
{
	struct lttcomm_metadata_request_msg request;
	struct lttcomm_consumer_msg msg;
	enum lttng_error_code ret_code = LTTNG_OK;
	uint64_t len, key, offset;
	int ret;

	assert(channel);
	assert(channel->metadata_cache);

	/* send the metadata request to sessiond */
	switch (consumer_data.type) {
	case LTTNG_CONSUMER64_UST:
		request.bits_per_long = 64;
		break;
	case LTTNG_CONSUMER32_UST:
		request.bits_per_long = 32;
		break;
	default:
		request.bits_per_long = 0;
		break;
	}

	request.session_id = channel->session_id;
	request.session_id_per_pid = channel->session_id_per_pid;
	request.uid = channel->uid;
	request.key = channel->key;
	DBG("Sending metadata request to sessiond, session id %" PRIu64
			", per-pid %" PRIu64,
			channel->session_id,
			channel->session_id_per_pid);

	ret = lttcomm_send_unix_sock(ctx->consumer_metadata_socket, &request,
			sizeof(request));
	if (ret < 0) {
		ERR("Asking metadata to sessiond");
		goto end;
	}

	/* Receive the metadata from sessiond */
	ret = lttcomm_recv_unix_sock(ctx->consumer_metadata_socket, &msg,
			sizeof(msg));
	if (ret != sizeof(msg)) {
		DBG("Consumer received unexpected message size %d (expects %zu)",
			ret, sizeof(msg));
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_CMD);
		/*
		 * The ret value might 0 meaning an orderly shutdown but this is ok
		 * since the caller handles this.
		 */
		goto end;
	}

	if (msg.cmd_type == LTTNG_ERR_UND) {
		/* No registry found */
		(void) consumer_send_status_msg(ctx->consumer_metadata_socket,
				ret_code);
		ret = 0;
		goto end;
	} else if (msg.cmd_type != LTTNG_CONSUMER_PUSH_METADATA) {
		ERR("Unexpected cmd_type received %d", msg.cmd_type);
		ret = -1;
		goto end;
	}

	len = msg.u.push_metadata.len;
	key = msg.u.push_metadata.key;
	offset = msg.u.push_metadata.target_offset;

	assert(key == channel->key);
	if (len == 0) {
		DBG("No new metadata to receive for key %" PRIu64, key);
	}

	/* Tell session daemon we are ready to receive the metadata. */
	ret = consumer_send_status_msg(ctx->consumer_metadata_socket,
			LTTNG_OK);
	if (ret < 0 || len == 0) {
		/*
		 * Somehow, the session daemon is not responding anymore or there is
		 * nothing to receive.
		 */
		goto end;
	}

	ret_code = lttng_ustconsumer_recv_metadata(ctx->consumer_metadata_socket,
			key, offset, len, channel);
	if (ret_code >= 0) {
		/*
		 * Only send the status msg if the sessiond is alive meaning a positive
		 * ret code.
		 */
		(void) consumer_send_status_msg(ctx->consumer_metadata_socket, ret_code);
	}
	ret = 0;

end:
	return ret;
}
