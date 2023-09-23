/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <common/align.hpp>
#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/compat/poll.hpp>
#include <common/consumer/consumer-metadata-cache.hpp>
#include <common/consumer/consumer-stream.hpp>
#include <common/consumer/consumer-testpoint.hpp>
#include <common/consumer/consumer-timer.hpp>
#include <common/consumer/consumer.hpp>
#include <common/dynamic-array.hpp>
#include <common/index/ctf-index.hpp>
#include <common/index/index.hpp>
#include <common/io-hint.hpp>
#include <common/kernel-consumer/kernel-consumer.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/relayd/relayd.hpp>
#include <common/sessiond-comm/relayd.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/string-utils/format.hpp>
#include <common/time.hpp>
#include <common/trace-chunk-registry.hpp>
#include <common/trace-chunk.hpp>
#include <common/urcu.hpp>
#include <common/ust-consumer/ust-consumer.hpp>
#include <common/utils.hpp>

#include <bin/lttng-consumerd/health-consumerd.hpp>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

lttng_consumer_global_data the_consumer_data;

enum consumer_channel_action {
	CONSUMER_CHANNEL_ADD,
	CONSUMER_CHANNEL_DEL,
	CONSUMER_CHANNEL_QUIT,
};

namespace {
struct consumer_channel_msg {
	enum consumer_channel_action action;
	struct lttng_consumer_channel *chan; /* add */
	uint64_t key; /* del */
};

/*
 * Global hash table containing respectively metadata and data streams. The
 * stream element in this ht should only be updated by the metadata poll thread
 * for the metadata and the data poll thread for the data.
 */
struct lttng_ht *metadata_ht;
struct lttng_ht *data_ht;
} /* namespace */

/* Flag used to temporarily pause data consumption from testpoints. */
int data_consumption_paused;

/*
 * Flag to inform the polling thread to quit when all fd hung up. Updated by
 * the consumer_thread_receive_fds when it notices that all fds has hung up.
 * Also updated by the signal handler (consumer_should_exit()). Read by the
 * polling threads.
 */
int consumer_quit;

static const char *get_consumer_domain()
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return DEFAULT_KERNEL_TRACE_DIR;
	case LTTNG_CONSUMER64_UST:
		/* Fall-through. */
	case LTTNG_CONSUMER32_UST:
		return DEFAULT_UST_TRACE_DIR;
	default:
		abort();
	}
}

/*
 * Notify a thread lttng pipe to poll back again. This usually means that some
 * global state has changed so we just send back the thread in a poll wait
 * call.
 */
static void notify_thread_lttng_pipe(struct lttng_pipe *pipe)
{
	struct lttng_consumer_stream *null_stream = nullptr;

	LTTNG_ASSERT(pipe);

	(void) lttng_pipe_write(pipe, &null_stream, sizeof(null_stream)); /* NOLINT sizeof used on a
									     pointer. */
}

static void notify_health_quit_pipe(int *pipe)
{
	ssize_t ret;

	ret = lttng_write(pipe[1], "4", 1);
	if (ret < 1) {
		PERROR("write consumer health quit");
	}
}

static void notify_channel_pipe(struct lttng_consumer_local_data *ctx,
				struct lttng_consumer_channel *chan,
				uint64_t key,
				enum consumer_channel_action action)
{
	struct consumer_channel_msg msg;
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));

	msg.action = action;
	msg.chan = chan;
	msg.key = key;
	ret = lttng_write(ctx->consumer_channel_pipe[1], &msg, sizeof(msg));
	if (ret < sizeof(msg)) {
		PERROR("notify_channel_pipe write error");
	}
}

void notify_thread_del_channel(struct lttng_consumer_local_data *ctx, uint64_t key)
{
	notify_channel_pipe(ctx, nullptr, key, CONSUMER_CHANNEL_DEL);
}

static int read_channel_pipe(struct lttng_consumer_local_data *ctx,
			     struct lttng_consumer_channel **chan,
			     uint64_t *key,
			     enum consumer_channel_action *action)
{
	struct consumer_channel_msg msg;
	ssize_t ret;

	ret = lttng_read(ctx->consumer_channel_pipe[0], &msg, sizeof(msg));
	if (ret < sizeof(msg)) {
		ret = -1;
		goto error;
	}
	*action = msg.action;
	*chan = msg.chan;
	*key = msg.key;
error:
	return (int) ret;
}

/*
 * Cleanup the stream list of a channel. Those streams are not yet globally
 * visible
 */
static void clean_channel_stream_list(struct lttng_consumer_channel *channel)
{
	struct lttng_consumer_stream *stream, *stmp;

	LTTNG_ASSERT(channel);

	/* Delete streams that might have been left in the stream list. */
	cds_list_for_each_entry_safe (stream, stmp, &channel->streams.head, send_node) {
		/*
		 * Once a stream is added to this list, the buffers were created so we
		 * have a guarantee that this call will succeed. Setting the monitor
		 * mode to 0 so we don't lock nor try to delete the stream from the
		 * global hash table.
		 */
		stream->monitor = 0;
		consumer_stream_destroy(stream, nullptr);
	}
}

/*
 * Find a stream. The consumer_data.lock must be locked during this
 * call.
 */
static struct lttng_consumer_stream *find_stream(uint64_t key, struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct lttng_consumer_stream *stream = nullptr;

	LTTNG_ASSERT(ht);

	/* -1ULL keys are lookup failures */
	if (key == (uint64_t) -1ULL) {
		return nullptr;
	}

	lttng::urcu::read_lock_guard read_lock;

	lttng_ht_lookup(ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != nullptr) {
		stream = lttng::utils::container_of(node, &lttng_consumer_stream::node);
	}

	return stream;
}

static void steal_stream_key(uint64_t key, struct lttng_ht *ht)
{
	struct lttng_consumer_stream *stream;

	lttng::urcu::read_lock_guard read_lock;
	stream = find_stream(key, ht);
	if (stream) {
		stream->key = (uint64_t) -1ULL;
		/*
		 * We don't want the lookup to match, but we still need
		 * to iterate on this stream when iterating over the hash table. Just
		 * change the node key.
		 */
		stream->node.key = (uint64_t) -1ULL;
	}
}

/*
 * Return a channel object for the given key.
 *
 * RCU read side lock MUST be acquired before calling this function and
 * protects the channel ptr.
 */
struct lttng_consumer_channel *consumer_find_channel(uint64_t key)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct lttng_consumer_channel *channel = nullptr;

	ASSERT_RCU_READ_LOCKED();

	/* -1ULL keys are lookup failures */
	if (key == (uint64_t) -1ULL) {
		return nullptr;
	}

	lttng_ht_lookup(the_consumer_data.channel_ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != nullptr) {
		channel = lttng::utils::container_of(node, &lttng_consumer_channel::node);
	}

	return channel;
}

/*
 * There is a possibility that the consumer does not have enough time between
 * the close of the channel on the session daemon and the cleanup in here thus
 * once we have a channel add with an existing key, we know for sure that this
 * channel will eventually get cleaned up by all streams being closed.
 *
 * This function just nullifies the already existing channel key.
 */
static void steal_channel_key(uint64_t key)
{
	struct lttng_consumer_channel *channel;

	lttng::urcu::read_lock_guard read_lock;
	channel = consumer_find_channel(key);
	if (channel) {
		channel->key = (uint64_t) -1ULL;
		/*
		 * We don't want the lookup to match, but we still need to iterate on
		 * this channel when iterating over the hash table. Just change the
		 * node key.
		 */
		channel->node.key = (uint64_t) -1ULL;
	}
}

static void free_channel_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node = lttng::utils::container_of(head, &lttng_ht_node_u64::head);
	struct lttng_consumer_channel *channel =
		lttng::utils::container_of(node, &lttng_consumer_channel::node);

	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		lttng_ustconsumer_free_channel(channel);
		break;
	default:
		ERR("Unknown consumer_data type");
		abort();
	}

	delete channel;
}

/*
 * RCU protected relayd socket pair free.
 */
static void free_relayd_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node = lttng::utils::container_of(head, &lttng_ht_node_u64::head);
	struct consumer_relayd_sock_pair *relayd =
		lttng::utils::container_of(node, &consumer_relayd_sock_pair::node);

	/*
	 * Close all sockets. This is done in the call RCU since we don't want the
	 * socket fds to be reassigned thus potentially creating bad state of the
	 * relayd object.
	 *
	 * We do not have to lock the control socket mutex here since at this stage
	 * there is no one referencing to this relayd object.
	 */
	(void) relayd_close(&relayd->control_sock);
	(void) relayd_close(&relayd->data_sock);

	pthread_mutex_destroy(&relayd->ctrl_sock_mutex);
	free(relayd);
}

/*
 * Destroy and free relayd socket pair object.
 */
void consumer_destroy_relayd(struct consumer_relayd_sock_pair *relayd)
{
	int ret;
	struct lttng_ht_iter iter;

	if (relayd == nullptr) {
		return;
	}

	DBG("Consumer destroy and close relayd socket pair");

	iter.iter.node = &relayd->node.node;
	ret = lttng_ht_del(the_consumer_data.relayd_ht, &iter);
	if (ret != 0) {
		/* We assume the relayd is being or is destroyed */
		return;
	}

	/* RCU free() call */
	call_rcu(&relayd->node.head, free_relayd_rcu);
}

/*
 * Remove a channel from the global list protected by a mutex. This function is
 * also responsible for freeing its data structures.
 */
void consumer_del_channel(struct lttng_consumer_channel *channel)
{
	struct lttng_ht_iter iter;

	DBG("Consumer delete channel key %" PRIu64, channel->key);

	pthread_mutex_lock(&the_consumer_data.lock);
	pthread_mutex_lock(&channel->lock);

	/* Destroy streams that might have been left in the stream list. */
	clean_channel_stream_list(channel);

	if (channel->live_timer_enabled == 1) {
		consumer_timer_live_stop(channel);
	}
	if (channel->monitor_timer_enabled == 1) {
		consumer_timer_monitor_stop(channel);
	}

	/*
	 * Send a last buffer statistics sample to the session daemon
	 * to ensure it tracks the amount of data consumed by this channel.
	 */
	sample_and_send_channel_buffer_stats(channel);

	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		lttng_ustconsumer_del_channel(channel);
		break;
	default:
		ERR("Unknown consumer_data type");
		abort();
		goto end;
	}

	lttng_trace_chunk_put(channel->trace_chunk);
	channel->trace_chunk = nullptr;

	if (channel->is_published) {
		int ret;

		lttng::urcu::read_lock_guard read_lock;
		iter.iter.node = &channel->node.node;
		ret = lttng_ht_del(the_consumer_data.channel_ht, &iter);
		LTTNG_ASSERT(!ret);

		iter.iter.node = &channel->channels_by_session_id_ht_node.node;
		ret = lttng_ht_del(the_consumer_data.channels_by_session_id_ht, &iter);
		LTTNG_ASSERT(!ret);
	}

	channel->is_deleted = true;
	call_rcu(&channel->node.head, free_channel_rcu);
end:
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&the_consumer_data.lock);
}

/*
 * Iterate over the relayd hash table and destroy each element. Finally,
 * destroy the whole hash table.
 */
static void cleanup_relayd_ht()
{
	struct lttng_ht_iter iter;
	struct consumer_relayd_sock_pair *relayd;

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			the_consumer_data.relayd_ht->ht, &iter.iter, relayd, node.node) {
			consumer_destroy_relayd(relayd);
		}
	}

	lttng_ht_destroy(the_consumer_data.relayd_ht);
}

/*
 * Update the end point status of all streams having the given network sequence
 * index (relayd index).
 *
 * It's atomically set without having the stream mutex locked which is fine
 * because we handle the write/read race with a pipe wakeup for each thread.
 */
static void update_endpoint_status_by_netidx(uint64_t net_seq_idx,
					     enum consumer_endpoint_status status)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	DBG("Consumer set delete flag on stream by idx %" PRIu64, net_seq_idx);

	lttng::urcu::read_lock_guard read_lock;

	/* Let's begin with metadata */
	cds_lfht_for_each_entry (metadata_ht->ht, &iter.iter, stream, node.node) {
		if (stream->net_seq_idx == net_seq_idx) {
			uatomic_set(&stream->endpoint_status, status);
			stream->chan->metadata_pushed_wait_queue.wake_all();

			DBG("Delete flag set to metadata stream %d", stream->wait_fd);
		}
	}

	/* Follow up by the data streams */
	cds_lfht_for_each_entry (data_ht->ht, &iter.iter, stream, node.node) {
		if (stream->net_seq_idx == net_seq_idx) {
			uatomic_set(&stream->endpoint_status, status);
			DBG("Delete flag set to data stream %d", stream->wait_fd);
		}
	}
}

/*
 * Cleanup a relayd object by flagging every associated streams for deletion,
 * destroying the object meaning removing it from the relayd hash table,
 * closing the sockets and freeing the memory in a RCU call.
 *
 * If a local data context is available, notify the threads that the streams'
 * state have changed.
 */
void lttng_consumer_cleanup_relayd(struct consumer_relayd_sock_pair *relayd)
{
	uint64_t netidx;

	LTTNG_ASSERT(relayd);

	DBG("Cleaning up relayd object ID %" PRIu64, relayd->net_seq_idx);

	/* Save the net sequence index before destroying the object */
	netidx = relayd->net_seq_idx;

	/*
	 * Delete the relayd from the relayd hash table, close the sockets and free
	 * the object in a RCU call.
	 */
	consumer_destroy_relayd(relayd);

	/* Set inactive endpoint to all streams */
	update_endpoint_status_by_netidx(netidx, CONSUMER_ENDPOINT_INACTIVE);

	/*
	 * With a local data context, notify the threads that the streams' state
	 * have changed. The write() action on the pipe acts as an "implicit"
	 * memory barrier ordering the updates of the end point status from the
	 * read of this status which happens AFTER receiving this notify.
	 */
	notify_thread_lttng_pipe(relayd->ctx->consumer_data_pipe);
	notify_thread_lttng_pipe(relayd->ctx->consumer_metadata_pipe);
}

/*
 * Flag a relayd socket pair for destruction. Destroy it if the refcount
 * reaches zero.
 *
 * RCU read side lock MUST be aquired before calling this function.
 */
void consumer_flag_relayd_for_destroy(struct consumer_relayd_sock_pair *relayd)
{
	LTTNG_ASSERT(relayd);
	ASSERT_RCU_READ_LOCKED();

	/* Set destroy flag for this object */
	uatomic_set(&relayd->destroy_flag, 1);

	/* Destroy the relayd if refcount is 0 */
	if (uatomic_read(&relayd->refcount) == 0) {
		consumer_destroy_relayd(relayd);
	}
}

/*
 * Completly destroy stream from every visiable data structure and the given
 * hash table if one.
 *
 * One this call returns, the stream object is not longer usable nor visible.
 */
void consumer_del_stream(struct lttng_consumer_stream *stream, struct lttng_ht *ht)
{
	consumer_stream_destroy(stream, ht);
}

/*
 * XXX naming of del vs destroy is all mixed up.
 */
void consumer_del_stream_for_data(struct lttng_consumer_stream *stream)
{
	consumer_stream_destroy(stream, data_ht);
}

void consumer_del_stream_for_metadata(struct lttng_consumer_stream *stream)
{
	consumer_stream_destroy(stream, metadata_ht);
}

void consumer_stream_update_channel_attributes(struct lttng_consumer_stream *stream,
					       struct lttng_consumer_channel *channel)
{
	stream->channel_read_only_attributes.tracefile_size = channel->tracefile_size;
}

/*
 * Add a stream to the global list protected by a mutex.
 */
void consumer_add_data_stream(struct lttng_consumer_stream *stream)
{
	struct lttng_ht *ht = data_ht;

	LTTNG_ASSERT(stream);
	LTTNG_ASSERT(ht);

	DBG3("Adding consumer stream %" PRIu64, stream->key);

	pthread_mutex_lock(&the_consumer_data.lock);
	pthread_mutex_lock(&stream->chan->lock);
	pthread_mutex_lock(&stream->chan->timer_lock);
	pthread_mutex_lock(&stream->lock);
	lttng::urcu::read_lock_guard read_lock;

	/* Steal stream identifier to avoid having streams with the same key */
	steal_stream_key(stream->key, ht);

	lttng_ht_add_unique_u64(ht, &stream->node);

	lttng_ht_add_u64(the_consumer_data.stream_per_chan_id_ht, &stream->node_channel_id);

	/*
	 * Add stream to the stream_list_ht of the consumer data. No need to steal
	 * the key since the HT does not use it and we allow to add redundant keys
	 * into this table.
	 */
	lttng_ht_add_u64(the_consumer_data.stream_list_ht, &stream->node_session_id);

	/*
	 * When nb_init_stream_left reaches 0, we don't need to trigger any action
	 * in terms of destroying the associated channel, because the action that
	 * causes the count to become 0 also causes a stream to be added. The
	 * channel deletion will thus be triggered by the following removal of this
	 * stream.
	 */
	if (uatomic_read(&stream->chan->nb_init_stream_left) > 0) {
		/* Increment refcount before decrementing nb_init_stream_left */
		cmm_smp_wmb();
		uatomic_dec(&stream->chan->nb_init_stream_left);
	}

	/* Update consumer data once the node is inserted. */
	the_consumer_data.stream_count++;
	the_consumer_data.need_update = 1;

	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&stream->chan->timer_lock);
	pthread_mutex_unlock(&stream->chan->lock);
	pthread_mutex_unlock(&the_consumer_data.lock);
}

/*
 * Add relayd socket to global consumer data hashtable. RCU read side lock MUST
 * be acquired before calling this.
 */
static int add_relayd(struct consumer_relayd_sock_pair *relayd)
{
	int ret = 0;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(relayd);
	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(the_consumer_data.relayd_ht, &relayd->net_seq_idx, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != nullptr) {
		goto end;
	}
	lttng_ht_add_unique_u64(the_consumer_data.relayd_ht, &relayd->node);

end:
	return ret;
}

/*
 * Allocate and return a consumer relayd socket.
 */
static struct consumer_relayd_sock_pair *consumer_allocate_relayd_sock_pair(uint64_t net_seq_idx)
{
	struct consumer_relayd_sock_pair *obj = nullptr;

	/* net sequence index of -1 is a failure */
	if (net_seq_idx == (uint64_t) -1ULL) {
		goto error;
	}

	obj = zmalloc<consumer_relayd_sock_pair>();
	if (obj == nullptr) {
		PERROR("zmalloc relayd sock");
		goto error;
	}

	obj->net_seq_idx = net_seq_idx;
	obj->refcount = 0;
	obj->destroy_flag = 0;
	obj->control_sock.sock.fd = -1;
	obj->data_sock.sock.fd = -1;
	lttng_ht_node_init_u64(&obj->node, obj->net_seq_idx);
	pthread_mutex_init(&obj->ctrl_sock_mutex, nullptr);

error:
	return obj;
}

/*
 * Find a relayd socket pair in the global consumer data.
 *
 * Return the object if found else NULL.
 * RCU read-side lock must be held across this call and while using the
 * returned object.
 */
struct consumer_relayd_sock_pair *consumer_find_relayd(uint64_t key)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct consumer_relayd_sock_pair *relayd = nullptr;

	ASSERT_RCU_READ_LOCKED();

	/* Negative keys are lookup failures */
	if (key == (uint64_t) -1ULL) {
		goto error;
	}

	lttng_ht_lookup(the_consumer_data.relayd_ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != nullptr) {
		relayd = lttng::utils::container_of(node, &consumer_relayd_sock_pair::node);
	}

error:
	return relayd;
}

/*
 * Find a relayd and send the stream
 *
 * Returns 0 on success, < 0 on error
 */
int consumer_send_relayd_stream(struct lttng_consumer_stream *stream, char *path)
{
	int ret = 0;
	struct consumer_relayd_sock_pair *relayd;

	LTTNG_ASSERT(stream);
	LTTNG_ASSERT(stream->net_seq_idx != -1ULL);
	LTTNG_ASSERT(path);

	/* The stream is not metadata. Get relayd reference if exists. */
	lttng::urcu::read_lock_guard read_lock;
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd != nullptr) {
		/* Add stream on the relayd */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_add_stream(&relayd->control_sock,
					stream->name,
					get_consumer_domain(),
					path,
					&stream->relayd_stream_id,
					stream->chan->tracefile_size,
					stream->chan->tracefile_count,
					stream->trace_chunk);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
			ERR("Relayd add stream failed. Cleaning up relayd %" PRIu64 ".",
			    relayd->net_seq_idx);
			lttng_consumer_cleanup_relayd(relayd);
			goto end;
		}

		uatomic_inc(&relayd->refcount);
		stream->sent_to_relayd = 1;
	} else {
		ERR("Stream %" PRIu64 " relayd ID %" PRIu64 " unknown. Can't send it.",
		    stream->key,
		    stream->net_seq_idx);
		ret = -1;
		goto end;
	}

	DBG("Stream %s with key %" PRIu64 " sent to relayd id %" PRIu64,
	    stream->name,
	    stream->key,
	    stream->net_seq_idx);

end:
	return ret;
}

/*
 * Find a relayd and send the streams sent message
 *
 * Returns 0 on success, < 0 on error
 */
int consumer_send_relayd_streams_sent(uint64_t net_seq_idx)
{
	int ret = 0;
	struct consumer_relayd_sock_pair *relayd;

	LTTNG_ASSERT(net_seq_idx != -1ULL);

	/* The stream is not metadata. Get relayd reference if exists. */
	lttng::urcu::read_lock_guard read_lock;
	relayd = consumer_find_relayd(net_seq_idx);
	if (relayd != nullptr) {
		/* Add stream on the relayd */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_streams_sent(&relayd->control_sock);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
			ERR("Relayd streams sent failed. Cleaning up relayd %" PRIu64 ".",
			    relayd->net_seq_idx);
			lttng_consumer_cleanup_relayd(relayd);
			goto end;
		}
	} else {
		ERR("Relayd ID %" PRIu64 " unknown. Can't send streams_sent.", net_seq_idx);
		ret = -1;
		goto end;
	}

	ret = 0;
	DBG("All streams sent relayd id %" PRIu64, net_seq_idx);

end:
	return ret;
}

/*
 * Find a relayd and close the stream
 */
void close_relayd_stream(struct lttng_consumer_stream *stream)
{
	struct consumer_relayd_sock_pair *relayd;

	/* The stream is not metadata. Get relayd reference if exists. */
	lttng::urcu::read_lock_guard read_lock;
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd) {
		consumer_stream_relayd_close(stream, relayd);
	}
}

/*
 * Handle stream for relayd transmission if the stream applies for network
 * streaming where the net sequence index is set.
 *
 * Return destination file descriptor or negative value on error.
 */
static int write_relayd_stream_header(struct lttng_consumer_stream *stream,
				      size_t data_size,
				      unsigned long padding,
				      struct consumer_relayd_sock_pair *relayd)
{
	int outfd = -1, ret;
	struct lttcomm_relayd_data_hdr data_hdr;

	/* Safety net */
	LTTNG_ASSERT(stream);
	LTTNG_ASSERT(relayd);

	/* Reset data header */
	memset(&data_hdr, 0, sizeof(data_hdr));

	if (stream->metadata_flag) {
		/* Caller MUST acquire the relayd control socket lock */
		ret = relayd_send_metadata(&relayd->control_sock, data_size);
		if (ret < 0) {
			goto error;
		}

		/* Metadata are always sent on the control socket. */
		outfd = relayd->control_sock.sock.fd;
	} else {
		/* Set header with stream information */
		data_hdr.stream_id = htobe64(stream->relayd_stream_id);
		data_hdr.data_size = htobe32(data_size);
		data_hdr.padding_size = htobe32(padding);

		/*
		 * Note that net_seq_num below is assigned with the *current* value of
		 * next_net_seq_num and only after that the next_net_seq_num will be
		 * increment. This is why when issuing a command on the relayd using
		 * this next value, 1 should always be substracted in order to compare
		 * the last seen sequence number on the relayd side to the last sent.
		 */
		data_hdr.net_seq_num = htobe64(stream->next_net_seq_num);
		/* Other fields are zeroed previously */

		ret = relayd_send_data_hdr(&relayd->data_sock, &data_hdr, sizeof(data_hdr));
		if (ret < 0) {
			goto error;
		}

		++stream->next_net_seq_num;

		/* Set to go on data socket */
		outfd = relayd->data_sock.sock.fd;
	}

error:
	return outfd;
}

/*
 * Write a character on the metadata poll pipe to wake the metadata thread.
 * Returns 0 on success, -1 on error.
 */
int consumer_metadata_wakeup_pipe(const struct lttng_consumer_channel *channel)
{
	int ret = 0;

	DBG("Waking up metadata poll thread (writing to pipe): channel name = '%s'", channel->name);
	if (channel->monitor && channel->metadata_stream) {
		const char dummy = 'c';
		const ssize_t write_ret =
			lttng_write(channel->metadata_stream->ust_metadata_poll_pipe[1], &dummy, 1);

		if (write_ret < 1) {
			if (errno == EWOULDBLOCK) {
				/*
				 * This is fine, the metadata poll thread
				 * is having a hard time keeping-up, but
				 * it will eventually wake-up and consume
				 * the available data.
				 */
				ret = 0;
			} else {
				PERROR("Failed to write to UST metadata pipe while attempting to wake-up the metadata poll thread");
				ret = -1;
				goto end;
			}
		}
	}

end:
	return ret;
}

/*
 * Trigger a dump of the metadata content. Following/during the succesful
 * completion of this call, the metadata poll thread will start receiving
 * metadata packets to consume.
 *
 * The caller must hold the channel and stream locks.
 */
static int consumer_metadata_stream_dump(struct lttng_consumer_stream *stream)
{
	int ret;

	ASSERT_LOCKED(stream->chan->lock);
	ASSERT_LOCKED(stream->lock);
	LTTNG_ASSERT(stream->metadata_flag);
	LTTNG_ASSERT(stream->chan->trace_chunk);

	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		/*
		 * Reset the position of what has been read from the
		 * metadata cache to 0 so we can dump it again.
		 */
		ret = kernctl_metadata_cache_dump(stream->wait_fd);
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		/*
		 * Reset the position pushed from the metadata cache so it
		 * will write from the beginning on the next push.
		 */
		stream->ust_metadata_pushed = 0;
		ret = consumer_metadata_wakeup_pipe(stream->chan);
		break;
	default:
		ERR("Unknown consumer_data type");
		abort();
	}
	if (ret < 0) {
		ERR("Failed to dump the metadata cache");
	}
	return ret;
}

static int lttng_consumer_channel_set_trace_chunk(struct lttng_consumer_channel *channel,
						  struct lttng_trace_chunk *new_trace_chunk)
{
	pthread_mutex_lock(&channel->lock);
	if (channel->is_deleted) {
		/*
		 * The channel has been logically deleted and should no longer
		 * be used. It has released its reference to its current trace
		 * chunk and should not acquire a new one.
		 *
		 * Return success as there is nothing for the caller to do.
		 */
		goto end;
	}

	/*
	 * The acquisition of the reference cannot fail (barring
	 * a severe internal error) since a reference to the published
	 * chunk is already held by the caller.
	 */
	if (new_trace_chunk) {
		const bool acquired_reference = lttng_trace_chunk_get(new_trace_chunk);

		LTTNG_ASSERT(acquired_reference);
	}

	lttng_trace_chunk_put(channel->trace_chunk);
	channel->trace_chunk = new_trace_chunk;
end:
	pthread_mutex_unlock(&channel->lock);
	return 0;
}

/*
 * Allocate and return a new lttng_consumer_channel object using the given key
 * to initialize the hash table node.
 *
 * On error, return NULL.
 */
struct lttng_consumer_channel *consumer_allocate_channel(uint64_t key,
							 uint64_t session_id,
							 const uint64_t *chunk_id,
							 const char *pathname,
							 const char *name,
							 uint64_t relayd_id,
							 enum lttng_event_output output,
							 uint64_t tracefile_size,
							 uint64_t tracefile_count,
							 uint64_t session_id_per_pid,
							 unsigned int monitor,
							 unsigned int live_timer_interval,
							 bool is_in_live_session,
							 const char *root_shm_path,
							 const char *shm_path)
{
	struct lttng_consumer_channel *channel = nullptr;
	struct lttng_trace_chunk *trace_chunk = nullptr;

	if (chunk_id) {
		trace_chunk = lttng_trace_chunk_registry_find_chunk(
			the_consumer_data.chunk_registry, session_id, *chunk_id);
		if (!trace_chunk) {
			ERR("Failed to find trace chunk reference during creation of channel");
			goto end;
		}
	}

	try {
		channel = new lttng_consumer_channel;
	} catch (const std::bad_alloc& e) {
		ERR("Failed to allocate lttng_consumer_channel: %s", e.what());
		channel = nullptr;
		goto end;
	}

	channel->key = key;
	channel->refcount = 0;
	channel->session_id = session_id;
	channel->session_id_per_pid = session_id_per_pid;
	channel->relayd_id = relayd_id;
	channel->tracefile_size = tracefile_size;
	channel->tracefile_count = tracefile_count;
	channel->monitor = monitor;
	channel->live_timer_interval = live_timer_interval;
	channel->is_live = is_in_live_session;
	pthread_mutex_init(&channel->lock, NULL);
	pthread_mutex_init(&channel->timer_lock, NULL);

	switch (output) {
	case LTTNG_EVENT_SPLICE:
		channel->output = CONSUMER_CHANNEL_SPLICE;
		break;
	case LTTNG_EVENT_MMAP:
		channel->output = CONSUMER_CHANNEL_MMAP;
		break;
	default:
		abort();
		delete channel;
		channel = nullptr;
		goto end;
	}

	/*
	 * In monitor mode, the streams associated with the channel will be put in
	 * a special list ONLY owned by this channel. So, the refcount is set to 1
	 * here meaning that the channel itself has streams that are referenced.
	 *
	 * On a channel deletion, once the channel is no longer visible, the
	 * refcount is decremented and checked for a zero value to delete it. With
	 * streams in no monitor mode, it will now be safe to destroy the channel.
	 */
	if (!channel->monitor) {
		channel->refcount = 1;
	}

	strncpy(channel->pathname, pathname, sizeof(channel->pathname));
	channel->pathname[sizeof(channel->pathname) - 1] = '\0';

	strncpy(channel->name, name, sizeof(channel->name));
	channel->name[sizeof(channel->name) - 1] = '\0';

	if (root_shm_path) {
		strncpy(channel->root_shm_path, root_shm_path, sizeof(channel->root_shm_path));
		channel->root_shm_path[sizeof(channel->root_shm_path) - 1] = '\0';
	}
	if (shm_path) {
		strncpy(channel->shm_path, shm_path, sizeof(channel->shm_path));
		channel->shm_path[sizeof(channel->shm_path) - 1] = '\0';
	}

	lttng_ht_node_init_u64(&channel->node, channel->key);
	lttng_ht_node_init_u64(&channel->channels_by_session_id_ht_node, channel->session_id);

	channel->wait_fd = -1;
	CDS_INIT_LIST_HEAD(&channel->streams.head);

	if (trace_chunk) {
		int ret = lttng_consumer_channel_set_trace_chunk(channel, trace_chunk);
		if (ret) {
			goto error;
		}
	}

	DBG("Allocated channel (key %" PRIu64 ")", channel->key);

end:
	lttng_trace_chunk_put(trace_chunk);
	return channel;
error:
	consumer_del_channel(channel);
	channel = nullptr;
	goto end;
}

/*
 * Add a channel to the global list protected by a mutex.
 *
 * Always return 0 indicating success.
 */
int consumer_add_channel(struct lttng_consumer_channel *channel,
			 struct lttng_consumer_local_data *ctx)
{
	pthread_mutex_lock(&the_consumer_data.lock);
	pthread_mutex_lock(&channel->lock);
	pthread_mutex_lock(&channel->timer_lock);

	/*
	 * This gives us a guarantee that the channel we are about to add to the
	 * channel hash table will be unique. See this function comment on the why
	 * we need to steel the channel key at this stage.
	 */
	steal_channel_key(channel->key);

	lttng::urcu::read_lock_guard read_lock;
	lttng_ht_add_unique_u64(the_consumer_data.channel_ht, &channel->node);
	lttng_ht_add_u64(the_consumer_data.channels_by_session_id_ht,
			 &channel->channels_by_session_id_ht_node);
	channel->is_published = true;

	pthread_mutex_unlock(&channel->timer_lock);
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&the_consumer_data.lock);

	if (channel->wait_fd != -1 && channel->type == CONSUMER_CHANNEL_TYPE_DATA) {
		notify_channel_pipe(ctx, channel, -1, CONSUMER_CHANNEL_ADD);
	}

	return 0;
}

/*
 * Allocate the pollfd structure and the local view of the out fds to avoid
 * doing a lookup in the linked list and concurrency issues when writing is
 * needed. Called with consumer_data.lock held.
 *
 * Returns the number of fds in the structures.
 */
static int update_poll_array(struct lttng_consumer_local_data *ctx,
			     struct pollfd **pollfd,
			     struct lttng_consumer_stream **local_stream,
			     struct lttng_ht *ht,
			     int *nb_inactive_fd)
{
	int i = 0;
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	LTTNG_ASSERT(ctx);
	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(pollfd);
	LTTNG_ASSERT(local_stream);

	DBG("Updating poll fd array");
	*nb_inactive_fd = 0;

	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_for_each_entry (ht->ht, &iter.iter, stream, node.node) {
			/*
			 * Only active streams with an active end point can be added to the
			 * poll set and local stream storage of the thread.
			 *
			 * There is a potential race here for endpoint_status to be updated
			 * just after the check. However, this is OK since the stream(s) will
			 * be deleted once the thread is notified that the end point state has
			 * changed where this function will be called back again.
			 *
			 * We track the number of inactive FDs because they still need to be
			 * closed by the polling thread after a wakeup on the data_pipe or
			 * metadata_pipe.
			 */
			if (stream->endpoint_status == CONSUMER_ENDPOINT_INACTIVE) {
				(*nb_inactive_fd)++;
				continue;
			}

			(*pollfd)[i].fd = stream->wait_fd;
			(*pollfd)[i].events = POLLIN | POLLPRI;
			local_stream[i] = stream;
			i++;
		}
	}

	/*
	 * Insert the consumer_data_pipe at the end of the array and don't
	 * increment i so nb_fd is the number of real FD.
	 */
	(*pollfd)[i].fd = lttng_pipe_get_readfd(ctx->consumer_data_pipe);
	(*pollfd)[i].events = POLLIN | POLLPRI;

	(*pollfd)[i + 1].fd = lttng_pipe_get_readfd(ctx->consumer_wakeup_pipe);
	(*pollfd)[i + 1].events = POLLIN | POLLPRI;
	return i;
}

/*
 * Poll on the should_quit pipe and the command socket return -1 on
 * error, 1 if should exit, 0 if data is available on the command socket
 */
int lttng_consumer_poll_socket(struct pollfd *consumer_sockpoll)
{
	int num_rdy;

restart:
	num_rdy = poll(consumer_sockpoll, 2, -1);
	if (num_rdy == -1) {
		/*
		 * Restart interrupted system call.
		 */
		if (errno == EINTR) {
			goto restart;
		}
		PERROR("Poll error");
		return -1;
	}
	if (consumer_sockpoll[0].revents & (POLLIN | POLLPRI)) {
		DBG("consumer_should_quit wake up");
		return 1;
	}
	return 0;
}

/*
 * Set the error socket.
 */
void lttng_consumer_set_error_sock(struct lttng_consumer_local_data *ctx, int sock)
{
	ctx->consumer_error_socket = sock;
}

/*
 * Set the command socket path.
 */
void lttng_consumer_set_command_sock_path(struct lttng_consumer_local_data *ctx, char *sock)
{
	ctx->consumer_command_sock_path = sock;
}

/*
 * Send return code to the session daemon.
 * If the socket is not defined, we return 0, it is not a fatal error
 */
int lttng_consumer_send_error(struct lttng_consumer_local_data *ctx, int cmd)
{
	if (ctx->consumer_error_socket > 0) {
		return lttcomm_send_unix_sock(
			ctx->consumer_error_socket, &cmd, sizeof(enum lttcomm_sessiond_command));
	}

	return 0;
}

/*
 * Close all the tracefiles and stream fds and MUST be called when all
 * instances are destroyed i.e. when all threads were joined and are ended.
 */
void lttng_consumer_cleanup()
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *channel;
	unsigned int trace_chunks_left;

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			the_consumer_data.channel_ht->ht, &iter.iter, channel, node.node) {
			consumer_del_channel(channel);
		}
	}

	lttng_ht_destroy(the_consumer_data.channel_ht);
	lttng_ht_destroy(the_consumer_data.channels_by_session_id_ht);

	cleanup_relayd_ht();

	lttng_ht_destroy(the_consumer_data.stream_per_chan_id_ht);

	/*
	 * This HT contains streams that are freed by either the metadata thread or
	 * the data thread so we do *nothing* on the hash table and simply destroy
	 * it.
	 */
	lttng_ht_destroy(the_consumer_data.stream_list_ht);

	/*
	 * Trace chunks in the registry may still exist if the session
	 * daemon has encountered an internal error and could not
	 * tear down its sessions and/or trace chunks properly.
	 *
	 * Release the session daemon's implicit reference to any remaining
	 * trace chunk and print an error if any trace chunk was found. Note
	 * that there are _no_ legitimate cases for trace chunks to be left,
	 * it is a leak. However, it can happen following a crash of the
	 * session daemon and not emptying the registry would cause an assertion
	 * to hit.
	 */
	trace_chunks_left =
		lttng_trace_chunk_registry_put_each_chunk(the_consumer_data.chunk_registry);
	if (trace_chunks_left) {
		ERR("%u trace chunks are leaked by lttng-consumerd. "
		    "This can be caused by an internal error of the session daemon.",
		    trace_chunks_left);
	}
	/* Run all callbacks freeing each chunk. */
	rcu_barrier();
	lttng_trace_chunk_registry_destroy(the_consumer_data.chunk_registry);
}

/*
 * Called from signal handler.
 */
void lttng_consumer_should_exit(struct lttng_consumer_local_data *ctx)
{
	ssize_t ret;

	CMM_STORE_SHARED(consumer_quit, 1);
	ret = lttng_write(ctx->consumer_should_quit[1], "4", 1);
	if (ret < 1) {
		PERROR("write consumer quit");
	}

	DBG("Consumer flag that it should quit");
}

/*
 * Flush pending writes to trace output disk file.
 */
static void lttng_consumer_sync_trace_file(struct lttng_consumer_stream *stream, off_t orig_offset)
{
	int outfd = stream->out_fd;

	/*
	 * This does a blocking write-and-wait on any page that belongs to the
	 * subbuffer prior to the one we just wrote.
	 * Don't care about error values, as these are just hints and ways to
	 * limit the amount of page cache used.
	 */
	if (orig_offset < stream->max_sb_size) {
		return;
	}
	lttng::io::hint_flush_range_dont_need_sync(
		outfd, orig_offset - stream->max_sb_size, stream->max_sb_size);
}

/*
 * Initialise the necessary environnement :
 * - create a new context
 * - create the poll_pipe
 * - create the should_quit pipe (for signal handler)
 * - create the thread pipe (for splice)
 *
 * Takes a function pointer as argument, this function is called when data is
 * available on a buffer. This function is responsible to do the
 * kernctl_get_next_subbuf, read the data with mmap or splice depending on the
 * buffer configuration and then kernctl_put_next_subbuf at the end.
 *
 * Returns a pointer to the new context or NULL on error.
 */
struct lttng_consumer_local_data *
lttng_consumer_create(enum lttng_consumer_type type,
		      ssize_t (*buffer_ready)(struct lttng_consumer_stream *stream,
					      struct lttng_consumer_local_data *ctx,
					      bool locked_by_caller),
		      int (*recv_channel)(struct lttng_consumer_channel *channel),
		      int (*recv_stream)(struct lttng_consumer_stream *stream),
		      int (*update_stream)(uint64_t stream_key, uint32_t state))
{
	int ret;
	struct lttng_consumer_local_data *ctx;

	LTTNG_ASSERT(the_consumer_data.type == LTTNG_CONSUMER_UNKNOWN ||
		     the_consumer_data.type == type);
	the_consumer_data.type = type;

	ctx = zmalloc<lttng_consumer_local_data>();
	if (ctx == nullptr) {
		PERROR("allocating context");
		goto error;
	}

	ctx->consumer_error_socket = -1;
	ctx->consumer_metadata_socket = -1;
	pthread_mutex_init(&ctx->metadata_socket_lock, nullptr);
	/* assign the callbacks */
	ctx->on_buffer_ready = buffer_ready;
	ctx->on_recv_channel = recv_channel;
	ctx->on_recv_stream = recv_stream;
	ctx->on_update_stream = update_stream;

	ctx->consumer_data_pipe = lttng_pipe_open(0);
	if (!ctx->consumer_data_pipe) {
		goto error_poll_pipe;
	}

	ctx->consumer_wakeup_pipe = lttng_pipe_open(0);
	if (!ctx->consumer_wakeup_pipe) {
		goto error_wakeup_pipe;
	}

	ret = pipe(ctx->consumer_should_quit);
	if (ret < 0) {
		PERROR("Error creating recv pipe");
		goto error_quit_pipe;
	}

	ret = pipe(ctx->consumer_channel_pipe);
	if (ret < 0) {
		PERROR("Error creating channel pipe");
		goto error_channel_pipe;
	}

	ctx->consumer_metadata_pipe = lttng_pipe_open(0);
	if (!ctx->consumer_metadata_pipe) {
		goto error_metadata_pipe;
	}

	ctx->channel_monitor_pipe = -1;

	return ctx;

error_metadata_pipe:
	utils_close_pipe(ctx->consumer_channel_pipe);
error_channel_pipe:
	utils_close_pipe(ctx->consumer_should_quit);
error_quit_pipe:
	lttng_pipe_destroy(ctx->consumer_wakeup_pipe);
error_wakeup_pipe:
	lttng_pipe_destroy(ctx->consumer_data_pipe);
error_poll_pipe:
	free(ctx);
error:
	return nullptr;
}

/*
 * Iterate over all streams of the hashtable and free them properly.
 */
static void destroy_data_stream_ht(struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	if (ht == nullptr) {
		return;
	}

	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_for_each_entry (ht->ht, &iter.iter, stream, node.node) {
			/*
			 * Ignore return value since we are currently cleaning up so any error
			 * can't be handled.
			 */
			(void) consumer_del_stream(stream, ht);
		}
	}

	lttng_ht_destroy(ht);
}

/*
 * Iterate over all streams of the metadata hashtable and free them
 * properly.
 */
static void destroy_metadata_stream_ht(struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	if (ht == nullptr) {
		return;
	}

	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_for_each_entry (ht->ht, &iter.iter, stream, node.node) {
			/*
			 * Ignore return value since we are currently cleaning up so any error
			 * can't be handled.
			 */
			(void) consumer_del_metadata_stream(stream, ht);
		}
	}

	lttng_ht_destroy(ht);
}

/*
 * Close all fds associated with the instance and free the context.
 */
void lttng_consumer_destroy(struct lttng_consumer_local_data *ctx)
{
	int ret;

	DBG("Consumer destroying it. Closing everything.");

	if (!ctx) {
		return;
	}

	destroy_data_stream_ht(data_ht);
	destroy_metadata_stream_ht(metadata_ht);

	ret = close(ctx->consumer_error_socket);
	if (ret) {
		PERROR("close");
	}
	ret = close(ctx->consumer_metadata_socket);
	if (ret) {
		PERROR("close");
	}
	utils_close_pipe(ctx->consumer_channel_pipe);
	lttng_pipe_destroy(ctx->consumer_data_pipe);
	lttng_pipe_destroy(ctx->consumer_metadata_pipe);
	lttng_pipe_destroy(ctx->consumer_wakeup_pipe);
	utils_close_pipe(ctx->consumer_should_quit);

	unlink(ctx->consumer_command_sock_path);
	free(ctx);
}

/*
 * Write the metadata stream id on the specified file descriptor.
 */
static int
write_relayd_metadata_id(int fd, struct lttng_consumer_stream *stream, unsigned long padding)
{
	ssize_t ret;
	struct lttcomm_relayd_metadata_payload hdr;

	hdr.stream_id = htobe64(stream->relayd_stream_id);
	hdr.padding_size = htobe32(padding);
	ret = lttng_write(fd, (void *) &hdr, sizeof(hdr));
	if (ret < sizeof(hdr)) {
		/*
		 * This error means that the fd's end is closed so ignore the PERROR
		 * not to clubber the error output since this can happen in a normal
		 * code path.
		 */
		if (errno != EPIPE) {
			PERROR("write metadata stream id");
		}
		DBG3("Consumer failed to write relayd metadata id (errno: %d)", errno);
		/*
		 * Set ret to a negative value because if ret != sizeof(hdr), we don't
		 * handle writting the missing part so report that as an error and
		 * don't lie to the caller.
		 */
		ret = -1;
		goto end;
	}
	DBG("Metadata stream id %" PRIu64 " with padding %lu written before data",
	    stream->relayd_stream_id,
	    padding);

end:
	return (int) ret;
}

/*
 * Mmap the ring buffer, read it and write the data to the tracefile. This is a
 * core function for writing trace buffers to either the local filesystem or
 * the network.
 *
 * It must be called with the stream and the channel lock held.
 *
 * Careful review MUST be put if any changes occur!
 *
 * Returns the number of bytes written
 */
ssize_t lttng_consumer_on_read_subbuffer_mmap(struct lttng_consumer_stream *stream,
					      const struct lttng_buffer_view *buffer,
					      unsigned long padding)
{
	ssize_t ret = 0;
	off_t orig_offset = stream->out_fd_offset;
	/* Default is on the disk */
	int outfd = stream->out_fd;
	struct consumer_relayd_sock_pair *relayd = nullptr;
	unsigned int relayd_hang_up = 0;
	const size_t subbuf_content_size = buffer->size - padding;
	size_t write_len;

	/* RCU lock for the relayd pointer */
	lttng::urcu::read_lock_guard read_lock;
	LTTNG_ASSERT(stream->net_seq_idx != (uint64_t) -1ULL || stream->trace_chunk);

	/* Flag that the current stream if set for network streaming. */
	if (stream->net_seq_idx != (uint64_t) -1ULL) {
		relayd = consumer_find_relayd(stream->net_seq_idx);
		if (relayd == nullptr) {
			ret = -EPIPE;
			goto end;
		}
	}

	/* Handle stream on the relayd if the output is on the network */
	if (relayd) {
		unsigned long netlen = subbuf_content_size;

		/*
		 * Lock the control socket for the complete duration of the function
		 * since from this point on we will use the socket.
		 */
		if (stream->metadata_flag) {
			/* Metadata requires the control socket. */
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			if (stream->reset_metadata_flag) {
				ret = relayd_reset_metadata(&relayd->control_sock,
							    stream->relayd_stream_id,
							    stream->metadata_version);
				if (ret < 0) {
					relayd_hang_up = 1;
					goto write_error;
				}
				stream->reset_metadata_flag = 0;
			}
			netlen += sizeof(struct lttcomm_relayd_metadata_payload);
		}

		ret = write_relayd_stream_header(stream, netlen, padding, relayd);
		if (ret < 0) {
			relayd_hang_up = 1;
			goto write_error;
		}
		/* Use the returned socket. */
		outfd = ret;

		/* Write metadata stream id before payload */
		if (stream->metadata_flag) {
			ret = write_relayd_metadata_id(outfd, stream, padding);
			if (ret < 0) {
				relayd_hang_up = 1;
				goto write_error;
			}
		}

		write_len = subbuf_content_size;
	} else {
		/* No streaming; we have to write the full padding. */
		if (stream->metadata_flag && stream->reset_metadata_flag) {
			ret = utils_truncate_stream_file(stream->out_fd, 0);
			if (ret < 0) {
				ERR("Reset metadata file");
				goto end;
			}
			stream->reset_metadata_flag = 0;
		}

		/*
		 * Check if we need to change the tracefile before writing the packet.
		 */
		if (stream->chan->tracefile_size > 0 &&
		    (stream->tracefile_size_current + buffer->size) >
			    stream->chan->tracefile_size) {
			ret = consumer_stream_rotate_output_files(stream);
			if (ret) {
				goto end;
			}
			outfd = stream->out_fd;
			orig_offset = 0;
		}
		stream->tracefile_size_current += buffer->size;
		write_len = buffer->size;
	}

	/*
	 * This call guarantee that len or less is returned. It's impossible to
	 * receive a ret value that is bigger than len.
	 */
	ret = lttng_write(outfd, buffer->data, write_len);
	DBG("Consumer mmap write() ret %zd (len %zu)", ret, write_len);
	if (ret < 0 || ((size_t) ret != write_len)) {
		/*
		 * Report error to caller if nothing was written else at least send the
		 * amount written.
		 */
		if (ret < 0) {
			ret = -errno;
		}
		relayd_hang_up = 1;

		/* Socket operation failed. We consider the relayd dead */
		if (errno == EPIPE) {
			/*
			 * This is possible if the fd is closed on the other side
			 * (outfd) or any write problem. It can be verbose a bit for a
			 * normal execution if for instance the relayd is stopped
			 * abruptly. This can happen so set this to a DBG statement.
			 */
			DBG("Consumer mmap write detected relayd hang up");
		} else {
			/* Unhandled error, print it and stop function right now. */
			PERROR("Error in write mmap (ret %zd != write_len %zu)", ret, write_len);
		}
		goto write_error;
	}
	stream->output_written += ret;

	/* This call is useless on a socket so better save a syscall. */
	if (!relayd) {
		/* This won't block, but will start writeout asynchronously */
		lttng::io::hint_flush_range_async(outfd, stream->out_fd_offset, write_len);
		stream->out_fd_offset += write_len;
		lttng_consumer_sync_trace_file(stream, orig_offset);
	}

write_error:
	/*
	 * This is a special case that the relayd has closed its socket. Let's
	 * cleanup the relayd object and all associated streams.
	 */
	if (relayd && relayd_hang_up) {
		ERR("Relayd hangup. Cleaning up relayd %" PRIu64 ".", relayd->net_seq_idx);
		lttng_consumer_cleanup_relayd(relayd);
	}

end:
	/* Unlock only if ctrl socket used */
	if (relayd && stream->metadata_flag) {
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	}

	return ret;
}

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * It must be called with the stream lock held.
 *
 * Returns the number of bytes spliced.
 */
ssize_t lttng_consumer_on_read_subbuffer_splice(struct lttng_consumer_local_data *ctx,
						struct lttng_consumer_stream *stream,
						unsigned long len,
						unsigned long padding)
{
	ssize_t ret = 0, written = 0, ret_splice = 0;
	loff_t offset = 0;
	off_t orig_offset = stream->out_fd_offset;
	int fd = stream->wait_fd;
	/* Default is on the disk */
	int outfd = stream->out_fd;
	struct consumer_relayd_sock_pair *relayd = nullptr;
	int *splice_pipe;
	unsigned int relayd_hang_up = 0;

	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		/* Not supported for user space tracing */
		return -ENOSYS;
	default:
		ERR("Unknown consumer_data type");
		abort();
	}

	/* RCU lock for the relayd pointer */
	lttng::urcu::read_lock_guard read_lock;

	/* Flag that the current stream if set for network streaming. */
	if (stream->net_seq_idx != (uint64_t) -1ULL) {
		relayd = consumer_find_relayd(stream->net_seq_idx);
		if (relayd == nullptr) {
			written = -ret;
			goto end;
		}
	}
	splice_pipe = stream->splice_pipe;

	/* Write metadata stream id before payload */
	if (relayd) {
		unsigned long total_len = len;

		if (stream->metadata_flag) {
			/*
			 * Lock the control socket for the complete duration of the function
			 * since from this point on we will use the socket.
			 */
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);

			if (stream->reset_metadata_flag) {
				ret = relayd_reset_metadata(&relayd->control_sock,
							    stream->relayd_stream_id,
							    stream->metadata_version);
				if (ret < 0) {
					relayd_hang_up = 1;
					goto write_error;
				}
				stream->reset_metadata_flag = 0;
			}
			ret = write_relayd_metadata_id(splice_pipe[1], stream, padding);
			if (ret < 0) {
				written = ret;
				relayd_hang_up = 1;
				goto write_error;
			}

			total_len += sizeof(struct lttcomm_relayd_metadata_payload);
		}

		ret = write_relayd_stream_header(stream, total_len, padding, relayd);
		if (ret < 0) {
			written = ret;
			relayd_hang_up = 1;
			goto write_error;
		}
		/* Use the returned socket. */
		outfd = ret;
	} else {
		/* No streaming, we have to set the len with the full padding */
		len += padding;

		if (stream->metadata_flag && stream->reset_metadata_flag) {
			ret = utils_truncate_stream_file(stream->out_fd, 0);
			if (ret < 0) {
				ERR("Reset metadata file");
				goto end;
			}
			stream->reset_metadata_flag = 0;
		}
		/*
		 * Check if we need to change the tracefile before writing the packet.
		 */
		if (stream->chan->tracefile_size > 0 &&
		    (stream->tracefile_size_current + len) > stream->chan->tracefile_size) {
			ret = consumer_stream_rotate_output_files(stream);
			if (ret < 0) {
				written = ret;
				goto end;
			}
			outfd = stream->out_fd;
			orig_offset = 0;
		}
		stream->tracefile_size_current += len;
	}

	while (len > 0) {
		DBG("splice chan to pipe offset %lu of len %lu (fd : %d, pipe: %d)",
		    (unsigned long) offset,
		    len,
		    fd,
		    splice_pipe[1]);
		ret_splice = splice(
			fd, &offset, splice_pipe[1], nullptr, len, SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice chan to pipe, ret %zd", ret_splice);
		if (ret_splice < 0) {
			ret = errno;
			written = -ret;
			PERROR("Error in relay splice");
			goto splice_error;
		}

		/* Handle stream on the relayd if the output is on the network */
		if (relayd && stream->metadata_flag) {
			size_t metadata_payload_size =
				sizeof(struct lttcomm_relayd_metadata_payload);

			/* Update counter to fit the spliced data */
			ret_splice += metadata_payload_size;
			len += metadata_payload_size;
			/*
			 * We do this so the return value can match the len passed as
			 * argument to this function.
			 */
			written -= metadata_payload_size;
		}

		/* Splice data out */
		ret_splice = splice(splice_pipe[0],
				    nullptr,
				    outfd,
				    nullptr,
				    ret_splice,
				    SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("Consumer splice pipe to file (out_fd: %d), ret %zd", outfd, ret_splice);
		if (ret_splice < 0) {
			ret = errno;
			written = -ret;
			relayd_hang_up = 1;
			goto write_error;
		} else if (ret_splice > len) {
			/*
			 * We don't expect this code path to be executed but you never know
			 * so this is an extra protection agains a buggy splice().
			 */
			ret = errno;
			written += ret_splice;
			PERROR("Wrote more data than requested %zd (len: %lu)", ret_splice, len);
			goto splice_error;
		} else {
			/* All good, update current len and continue. */
			len -= ret_splice;
		}

		/* This call is useless on a socket so better save a syscall. */
		if (!relayd) {
			/* This won't block, but will start writeout asynchronously */
			lttng::io::hint_flush_range_async(outfd, stream->out_fd_offset, ret_splice);
			stream->out_fd_offset += ret_splice;
		}
		stream->output_written += ret_splice;
		written += ret_splice;
	}
	if (!relayd) {
		lttng_consumer_sync_trace_file(stream, orig_offset);
	}
	goto end;

write_error:
	/*
	 * This is a special case that the relayd has closed its socket. Let's
	 * cleanup the relayd object and all associated streams.
	 */
	if (relayd && relayd_hang_up) {
		ERR("Relayd hangup. Cleaning up relayd %" PRIu64 ".", relayd->net_seq_idx);
		lttng_consumer_cleanup_relayd(relayd);
		/* Skip splice error so the consumer does not fail */
		goto end;
	}

splice_error:
	/* send the appropriate error description to sessiond */
	switch (ret) {
	case EINVAL:
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_SPLICE_EINVAL);
		break;
	case ENOMEM:
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_SPLICE_ENOMEM);
		break;
	case ESPIPE:
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_SPLICE_ESPIPE);
		break;
	}

end:
	if (relayd && stream->metadata_flag) {
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	}

	return written;
}

/*
 * Sample the snapshot positions for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_sample_snapshot_positions(struct lttng_consumer_stream *stream)
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_sample_snapshot_positions(stream);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_sample_snapshot_positions(stream);
	default:
		ERR("Unknown consumer_data type");
		abort();
		return -ENOSYS;
	}
}
/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_take_snapshot(struct lttng_consumer_stream *stream)
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_take_snapshot(stream);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_take_snapshot(stream);
	default:
		ERR("Unknown consumer_data type");
		abort();
		return -ENOSYS;
	}
}

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_get_produced_snapshot(struct lttng_consumer_stream *stream, unsigned long *pos)
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_get_produced_snapshot(stream, pos);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_get_produced_snapshot(stream, pos);
	default:
		ERR("Unknown consumer_data type");
		abort();
		return -ENOSYS;
	}
}

/*
 * Get the consumed position (free-running counter position in bytes).
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_get_consumed_snapshot(struct lttng_consumer_stream *stream, unsigned long *pos)
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_get_consumed_snapshot(stream, pos);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_get_consumed_snapshot(stream, pos);
	default:
		ERR("Unknown consumer_data type");
		abort();
		return -ENOSYS;
	}
}

int lttng_consumer_recv_cmd(struct lttng_consumer_local_data *ctx,
			    int sock,
			    struct pollfd *consumer_sockpoll)
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_recv_cmd(ctx, sock, consumer_sockpoll);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_recv_cmd(ctx, sock, consumer_sockpoll);
	default:
		ERR("Unknown consumer_data type");
		abort();
		return -ENOSYS;
	}
}

static void lttng_consumer_close_all_metadata()
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		/*
		 * The Kernel consumer has a different metadata scheme so we don't
		 * close anything because the stream will be closed by the session
		 * daemon.
		 */
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		/*
		 * Close all metadata streams. The metadata hash table is passed and
		 * this call iterates over it by closing all wakeup fd. This is safe
		 * because at this point we are sure that the metadata producer is
		 * either dead or blocked.
		 */
		lttng_ustconsumer_close_all_metadata(metadata_ht);
		break;
	default:
		ERR("Unknown consumer_data type");
		abort();
	}
}

/*
 * Clean up a metadata stream and free its memory.
 */
void consumer_del_metadata_stream(struct lttng_consumer_stream *stream, struct lttng_ht *ht)
{
	struct lttng_consumer_channel *channel = nullptr;
	bool free_channel = false;

	LTTNG_ASSERT(stream);
	/*
	 * This call should NEVER receive regular stream. It must always be
	 * metadata stream and this is crucial for data structure synchronization.
	 */
	LTTNG_ASSERT(stream->metadata_flag);

	DBG3("Consumer delete metadata stream %d", stream->wait_fd);

	pthread_mutex_lock(&the_consumer_data.lock);
	/*
	 * Note that this assumes that a stream's channel is never changed and
	 * that the stream's lock doesn't need to be taken to sample its
	 * channel.
	 */
	channel = stream->chan;
	pthread_mutex_lock(&channel->lock);
	pthread_mutex_lock(&stream->lock);
	if (channel->metadata_cache) {
		/* Only applicable to userspace consumers. */
		pthread_mutex_lock(&channel->metadata_cache->lock);
	}

	/* Remove any reference to that stream. */
	consumer_stream_delete(stream, ht);

	/* Close down everything including the relayd if one. */
	consumer_stream_close_output(stream);
	/* Destroy tracer buffers of the stream. */
	consumer_stream_destroy_buffers(stream);

	/* Atomically decrement channel refcount since other threads can use it. */
	if (!uatomic_sub_return(&channel->refcount, 1) &&
	    !uatomic_read(&channel->nb_init_stream_left)) {
		/* Go for channel deletion! */
		free_channel = true;
	}
	stream->chan = nullptr;

	/*
	 * Nullify the stream reference so it is not used after deletion. The
	 * channel lock MUST be acquired before being able to check for a NULL
	 * pointer value.
	 */
	channel->metadata_stream = nullptr;
	channel->metadata_pushed_wait_queue.wake_all();

	if (channel->metadata_cache) {
		pthread_mutex_unlock(&channel->metadata_cache->lock);
	}
	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&the_consumer_data.lock);

	if (free_channel) {
		consumer_del_channel(channel);
	}

	lttng_trace_chunk_put(stream->trace_chunk);
	stream->trace_chunk = nullptr;
	consumer_stream_free(stream);
}

/*
 * Action done with the metadata stream when adding it to the consumer internal
 * data structures to handle it.
 */
void consumer_add_metadata_stream(struct lttng_consumer_stream *stream)
{
	struct lttng_ht *ht = metadata_ht;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;

	LTTNG_ASSERT(stream);
	LTTNG_ASSERT(ht);

	DBG3("Adding metadata stream %" PRIu64 " to hash table", stream->key);

	pthread_mutex_lock(&the_consumer_data.lock);
	pthread_mutex_lock(&stream->chan->lock);
	pthread_mutex_lock(&stream->chan->timer_lock);
	pthread_mutex_lock(&stream->lock);

	/*
	 * From here, refcounts are updated so be _careful_ when returning an error
	 * after this point.
	 */

	lttng::urcu::read_lock_guard read_lock;

	/*
	 * Lookup the stream just to make sure it does not exist in our internal
	 * state. This should NEVER happen.
	 */
	lttng_ht_lookup(ht, &stream->key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	LTTNG_ASSERT(!node);

	/*
	 * When nb_init_stream_left reaches 0, we don't need to trigger any action
	 * in terms of destroying the associated channel, because the action that
	 * causes the count to become 0 also causes a stream to be added. The
	 * channel deletion will thus be triggered by the following removal of this
	 * stream.
	 */
	if (uatomic_read(&stream->chan->nb_init_stream_left) > 0) {
		/* Increment refcount before decrementing nb_init_stream_left */
		cmm_smp_wmb();
		uatomic_dec(&stream->chan->nb_init_stream_left);
	}

	lttng_ht_add_unique_u64(ht, &stream->node);

	lttng_ht_add_u64(the_consumer_data.stream_per_chan_id_ht, &stream->node_channel_id);

	/*
	 * Add stream to the stream_list_ht of the consumer data. No need to steal
	 * the key since the HT does not use it and we allow to add redundant keys
	 * into this table.
	 */
	lttng_ht_add_u64(the_consumer_data.stream_list_ht, &stream->node_session_id);

	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&stream->chan->lock);
	pthread_mutex_unlock(&stream->chan->timer_lock);
	pthread_mutex_unlock(&the_consumer_data.lock);
}

/*
 * Delete data stream that are flagged for deletion (endpoint_status).
 */
static void validate_endpoint_status_data_stream()
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	DBG("Consumer delete flagged data stream");

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (data_ht->ht, &iter.iter, stream, node.node) {
			/* Validate delete flag of the stream */
			if (stream->endpoint_status == CONSUMER_ENDPOINT_ACTIVE) {
				continue;
			}
			/* Delete it right now */
			consumer_del_stream(stream, data_ht);
		}
	}
}

/*
 * Delete metadata stream that are flagged for deletion (endpoint_status).
 */
static void validate_endpoint_status_metadata_stream(struct lttng_poll_event *pollset)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	DBG("Consumer delete flagged metadata stream");

	LTTNG_ASSERT(pollset);

	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_for_each_entry (metadata_ht->ht, &iter.iter, stream, node.node) {
			/* Validate delete flag of the stream */
			if (stream->endpoint_status == CONSUMER_ENDPOINT_ACTIVE) {
				continue;
			}
			/*
			 * Remove from pollset so the metadata thread can continue without
			 * blocking on a deleted stream.
			 */
			lttng_poll_del(pollset, stream->wait_fd);

			/* Delete it right now */
			consumer_del_metadata_stream(stream, metadata_ht);
		}
	}
}

/*
 * Thread polls on metadata file descriptor and write them on disk or on the
 * network.
 */
void *consumer_thread_metadata_poll(void *data)
{
	int ret, i, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_consumer_stream *stream = nullptr;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct lttng_poll_event events;
	struct lttng_consumer_local_data *ctx = (lttng_consumer_local_data *) data;
	ssize_t len;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_METADATA);

	if (testpoint(consumerd_thread_metadata)) {
		goto error_testpoint;
	}

	health_code_update();

	DBG("Thread metadata poll started");

	/* Size is set to 1 for the consumer_metadata pipe */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		ERR("Poll set creation failed");
		goto end_poll;
	}

	ret = lttng_poll_add(&events, lttng_pipe_get_readfd(ctx->consumer_metadata_pipe), LPOLLIN);
	if (ret < 0) {
		goto end;
	}

	/* Main loop */
	DBG("Metadata main loop started");

	while (true) {
	restart:
		health_code_update();
		health_poll_entry();
		DBG("Metadata poll wait");
		ret = lttng_poll_wait(&events, -1);
		DBG("Metadata poll return from wait with %d fd(s)", LTTNG_POLL_GETNB(&events));
		health_poll_exit();
		DBG("Metadata event caught in thread");
		if (ret < 0) {
			if (errno == EINTR) {
				ERR("Poll EINTR caught");
				goto restart;
			}
			if (LTTNG_POLL_GETNB(&events) == 0) {
				err = 0; /* All is OK */
			}
			goto end;
		}

		nb_fd = ret;

		/* From here, the event is a metadata wait fd */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (pollfd == lttng_pipe_get_readfd(ctx->consumer_metadata_pipe)) {
				if (revents & LPOLLIN) {
					ssize_t pipe_len;

					pipe_len = lttng_pipe_read(ctx->consumer_metadata_pipe,
								   &stream,
								   sizeof(stream)); /* NOLINT sizeof
										       used on a
										       pointer. */
					if (pipe_len < sizeof(stream)) { /* NOLINT sizeof used on a
									    pointer. */
						if (pipe_len < 0) {
							PERROR("read metadata stream");
						}
						/*
						 * Remove the pipe from the poll set and continue
						 * the loop since their might be data to consume.
						 */
						lttng_poll_del(
							&events,
							lttng_pipe_get_readfd(
								ctx->consumer_metadata_pipe));
						lttng_pipe_read_close(ctx->consumer_metadata_pipe);
						continue;
					}

					/* A NULL stream means that the state has changed. */
					if (stream == nullptr) {
						/* Check for deleted streams. */
						validate_endpoint_status_metadata_stream(&events);
						goto restart;
					}

					DBG("Adding metadata stream %d to poll set",
					    stream->wait_fd);

					/* Add metadata stream to the global poll events list */
					lttng_poll_add(
						&events, stream->wait_fd, LPOLLIN | LPOLLPRI);
				} else if (revents & (LPOLLERR | LPOLLHUP)) {
					DBG("Metadata thread pipe hung up");
					/*
					 * Remove the pipe from the poll set and continue the loop
					 * since their might be data to consume.
					 */
					lttng_poll_del(
						&events,
						lttng_pipe_get_readfd(ctx->consumer_metadata_pipe));
					lttng_pipe_read_close(ctx->consumer_metadata_pipe);
					continue;
				} else {
					ERR("Unexpected poll events %u for sock %d",
					    revents,
					    pollfd);
					goto end;
				}

				/* Handle other stream */
				continue;
			}

			lttng::urcu::read_lock_guard read_lock;
			{
				uint64_t tmp_id = (uint64_t) pollfd;

				lttng_ht_lookup(metadata_ht, &tmp_id, &iter);
			}
			node = lttng_ht_iter_get_node_u64(&iter);
			LTTNG_ASSERT(node);

			stream = caa_container_of(node, struct lttng_consumer_stream, node);

			if (revents & (LPOLLIN | LPOLLPRI)) {
				/* Get the data out of the metadata file descriptor */
				DBG("Metadata available on fd %d", pollfd);
				LTTNG_ASSERT(stream->wait_fd == pollfd);

				do {
					health_code_update();

					len = ctx->on_buffer_ready(stream, ctx, false);
					/*
					 * We don't check the return value here since if we get
					 * a negative len, it means an error occurred thus we
					 * simply remove it from the poll set and free the
					 * stream.
					 */
				} while (len > 0);

				/* It's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					/* Clean up stream from consumer and free it. */
					lttng_poll_del(&events, stream->wait_fd);
					consumer_del_metadata_stream(stream, metadata_ht);
				}
			} else if (revents & (LPOLLERR | LPOLLHUP)) {
				DBG("Metadata fd %d is hup|err.", pollfd);
				if (!stream->hangup_flush_done &&
				    (the_consumer_data.type == LTTNG_CONSUMER32_UST ||
				     the_consumer_data.type == LTTNG_CONSUMER64_UST)) {
					DBG("Attempting to flush and consume the UST buffers");
					lttng_ustconsumer_on_stream_hangup(stream);

					/* We just flushed the stream now read it. */
					do {
						health_code_update();

						len = ctx->on_buffer_ready(stream, ctx, false);
						/*
						 * We don't check the return value here since if we
						 * get a negative len, it means an error occurred
						 * thus we simply remove it from the poll set and
						 * free the stream.
						 */
					} while (len > 0);
				}

				lttng_poll_del(&events, stream->wait_fd);
				/*
				 * This call update the channel states, closes file descriptors
				 * and securely free the stream.
				 */
				consumer_del_metadata_stream(stream, metadata_ht);
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto end;
			}
			/* Release RCU lock for the stream looked up */
		}
	}

	/* All is OK */
	err = 0;
end:
	DBG("Metadata poll thread exiting");

	lttng_poll_clean(&events);
end_poll:
error_testpoint:
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_consumerd);
	rcu_unregister_thread();
	return nullptr;
}

/*
 * This thread polls the fds in the set to consume the data and write
 * it to tracefile if necessary.
 */
void *consumer_thread_data_poll(void *data)
{
	int num_rdy, high_prio, ret, i, err = -1;
	struct pollfd *pollfd = nullptr;
	/* local view of the streams */
	struct lttng_consumer_stream **local_stream = nullptr, *new_stream = nullptr;
	/* local view of consumer_data.fds_count */
	int nb_fd = 0;
	/* 2 for the consumer_data_pipe and wake up pipe */
	const int nb_pipes_fd = 2;
	/* Number of FDs with CONSUMER_ENDPOINT_INACTIVE but still open. */
	int nb_inactive_fd = 0;
	struct lttng_consumer_local_data *ctx = (lttng_consumer_local_data *) data;
	ssize_t len;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_DATA);

	if (testpoint(consumerd_thread_data)) {
		goto error_testpoint;
	}

	health_code_update();

	local_stream = zmalloc<lttng_consumer_stream *>();
	if (local_stream == nullptr) {
		PERROR("local_stream malloc");
		goto end;
	}

	while (true) {
		health_code_update();

		high_prio = 0;

		/*
		 * the fds set has been updated, we need to update our
		 * local array as well
		 */
		pthread_mutex_lock(&the_consumer_data.lock);
		if (the_consumer_data.need_update) {
			free(pollfd);
			pollfd = nullptr;

			free(local_stream);
			local_stream = nullptr;

			/* Allocate for all fds */
			pollfd =
				calloc<struct pollfd>(the_consumer_data.stream_count + nb_pipes_fd);
			if (pollfd == nullptr) {
				PERROR("pollfd malloc");
				pthread_mutex_unlock(&the_consumer_data.lock);
				goto end;
			}

			local_stream = calloc<lttng_consumer_stream *>(
				the_consumer_data.stream_count + nb_pipes_fd);
			if (local_stream == nullptr) {
				PERROR("local_stream malloc");
				pthread_mutex_unlock(&the_consumer_data.lock);
				goto end;
			}
			ret = update_poll_array(
				ctx, &pollfd, local_stream, data_ht, &nb_inactive_fd);
			if (ret < 0) {
				ERR("Error in allocating pollfd or local_outfds");
				lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_POLL_ERROR);
				pthread_mutex_unlock(&the_consumer_data.lock);
				goto end;
			}
			nb_fd = ret;
			the_consumer_data.need_update = 0;
		}
		pthread_mutex_unlock(&the_consumer_data.lock);

		/* No FDs and consumer_quit, consumer_cleanup the thread */
		if (nb_fd == 0 && nb_inactive_fd == 0 && CMM_LOAD_SHARED(consumer_quit) == 1) {
			err = 0; /* All is OK */
			goto end;
		}
		/* poll on the array of fds */
	restart:
		DBG("polling on %d fd", nb_fd + nb_pipes_fd);
		if (testpoint(consumerd_thread_data_poll)) {
			goto end;
		}
		health_poll_entry();
		num_rdy = poll(pollfd, nb_fd + nb_pipes_fd, -1);
		health_poll_exit();
		DBG("poll num_rdy : %d", num_rdy);
		if (num_rdy == -1) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				goto restart;
			}
			PERROR("Poll error");
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_POLL_ERROR);
			goto end;
		} else if (num_rdy == 0) {
			DBG("Polling thread timed out");
			goto end;
		}

		if (caa_unlikely(data_consumption_paused)) {
			DBG("Data consumption paused, sleeping...");
			sleep(1);
			goto restart;
		}

		/*
		 * If the consumer_data_pipe triggered poll go directly to the
		 * beginning of the loop to update the array. We want to prioritize
		 * array update over low-priority reads.
		 */
		if (pollfd[nb_fd].revents & (POLLIN | POLLPRI)) {
			ssize_t pipe_readlen;

			DBG("consumer_data_pipe wake up");
			pipe_readlen = lttng_pipe_read(ctx->consumer_data_pipe,
						       &new_stream,
						       sizeof(new_stream)); /* NOLINT sizeof used on
									       a pointer. */
			if (pipe_readlen < sizeof(new_stream)) { /* NOLINT sizeof used on a pointer.
								  */
				PERROR("Consumer data pipe");
				/* Continue so we can at least handle the current stream(s). */
				continue;
			}

			/*
			 * If the stream is NULL, just ignore it. It's also possible that
			 * the sessiond poll thread changed the consumer_quit state and is
			 * waking us up to test it.
			 */
			if (new_stream == nullptr) {
				validate_endpoint_status_data_stream();
				continue;
			}

			/* Continue to update the local streams and handle prio ones */
			continue;
		}

		/* Handle wakeup pipe. */
		if (pollfd[nb_fd + 1].revents & (POLLIN | POLLPRI)) {
			char dummy;
			ssize_t pipe_readlen;

			pipe_readlen =
				lttng_pipe_read(ctx->consumer_wakeup_pipe, &dummy, sizeof(dummy));
			if (pipe_readlen < 0) {
				PERROR("Consumer data wakeup pipe");
			}
			/* We've been awakened to handle stream(s). */
			ctx->has_wakeup = 0;
		}

		/* Take care of high priority channels first. */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			if (local_stream[i] == nullptr) {
				continue;
			}
			if (pollfd[i].revents & POLLPRI) {
				DBG("Urgent read on fd %d", pollfd[i].fd);
				high_prio = 1;
				len = ctx->on_buffer_ready(local_stream[i], ctx, false);
				/* it's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					/* Clean the stream and free it. */
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = nullptr;
				} else if (len > 0) {
					local_stream[i]->has_data_left_to_be_read_before_teardown =
						1;
				}
			}
		}

		/*
		 * If we read high prio channel in this loop, try again
		 * for more high prio data.
		 */
		if (high_prio) {
			continue;
		}

		/* Take care of low priority channels. */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			if (local_stream[i] == nullptr) {
				continue;
			}
			if ((pollfd[i].revents & POLLIN) || local_stream[i]->hangup_flush_done ||
			    local_stream[i]->has_data) {
				DBG("Normal read on fd %d", pollfd[i].fd);
				len = ctx->on_buffer_ready(local_stream[i], ctx, false);
				/* it's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					/* Clean the stream and free it. */
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = nullptr;
				} else if (len > 0) {
					local_stream[i]->has_data_left_to_be_read_before_teardown =
						1;
				}
			}
		}

		/* Handle hangup and errors */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			if (local_stream[i] == nullptr) {
				continue;
			}
			if (!local_stream[i]->hangup_flush_done &&
			    (pollfd[i].revents & (POLLHUP | POLLERR | POLLNVAL)) &&
			    (the_consumer_data.type == LTTNG_CONSUMER32_UST ||
			     the_consumer_data.type == LTTNG_CONSUMER64_UST)) {
				DBG("fd %d is hup|err|nval. Attempting flush and read.",
				    pollfd[i].fd);
				lttng_ustconsumer_on_stream_hangup(local_stream[i]);
				/* Attempt read again, for the data we just flushed. */
				local_stream[i]->has_data_left_to_be_read_before_teardown = 1;
			}
			/*
			 * When a stream's pipe dies (hup/err/nval), an "inactive producer" flush is
			 * performed. This type of flush ensures that a new packet is produced no
			 * matter the consumed/produced positions are.
			 *
			 * This, in turn, causes the next pass to see that data available for the
			 * stream. When we come back here, we can be assured that all available
			 * data has been consumed and we can finally destroy the stream.
			 *
			 * If the poll flag is HUP/ERR/NVAL and we have
			 * read no data in this pass, we can remove the
			 * stream from its hash table.
			 */
			if ((pollfd[i].revents & POLLHUP)) {
				DBG("Polling fd %d tells it has hung up.", pollfd[i].fd);
				if (!local_stream[i]->has_data_left_to_be_read_before_teardown) {
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = nullptr;
				}
			} else if (pollfd[i].revents & POLLERR) {
				ERR("Error returned in polling fd %d.", pollfd[i].fd);
				if (!local_stream[i]->has_data_left_to_be_read_before_teardown) {
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = nullptr;
				}
			} else if (pollfd[i].revents & POLLNVAL) {
				ERR("Polling fd %d tells fd is not open.", pollfd[i].fd);
				if (!local_stream[i]->has_data_left_to_be_read_before_teardown) {
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = nullptr;
				}
			}
			if (local_stream[i] != nullptr) {
				local_stream[i]->has_data_left_to_be_read_before_teardown = 0;
			}
		}
	}
	/* All is OK */
	err = 0;
end:
	DBG("polling thread exiting");
	free(pollfd);
	free(local_stream);

	/*
	 * Close the write side of the pipe so epoll_wait() in
	 * consumer_thread_metadata_poll can catch it. The thread is monitoring the
	 * read side of the pipe. If we close them both, epoll_wait strangely does
	 * not return and could create a endless wait period if the pipe is the
	 * only tracked fd in the poll set. The thread will take care of closing
	 * the read side.
	 */
	(void) lttng_pipe_write_close(ctx->consumer_metadata_pipe);

error_testpoint:
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_consumerd);

	rcu_unregister_thread();
	return nullptr;
}

/*
 * Close wake-up end of each stream belonging to the channel. This will
 * allow the poll() on the stream read-side to detect when the
 * write-side (application) finally closes them.
 */
static void consumer_close_channel_streams(struct lttng_consumer_channel *channel)
{
	struct lttng_ht *ht;
	struct lttng_consumer_stream *stream;
	struct lttng_ht_iter iter;

	ht = the_consumer_data.stream_per_chan_id_ht;

	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_for_each_entry_duplicate(ht->ht,
					  ht->hash_fct(&channel->key, lttng_ht_seed),
					  ht->match_fct,
					  &channel->key,
					  &iter.iter,
					  stream,
					  node_channel_id.node)
	{
		/*
		 * Protect against teardown with mutex.
		 */
		pthread_mutex_lock(&stream->lock);
		if (cds_lfht_is_node_deleted(&stream->node.node)) {
			goto next;
		}
		switch (the_consumer_data.type) {
		case LTTNG_CONSUMER_KERNEL:
			break;
		case LTTNG_CONSUMER32_UST:
		case LTTNG_CONSUMER64_UST:
			if (stream->metadata_flag) {
				/* Safe and protected by the stream lock. */
				lttng_ustconsumer_close_metadata(stream->chan);
			} else {
				/*
				 * Note: a mutex is taken internally within
				 * liblttng-ust-ctl to protect timer wakeup_fd
				 * use from concurrent close.
				 */
				lttng_ustconsumer_close_stream_wakeup(stream);
			}
			break;
		default:
			ERR("Unknown consumer_data type");
			abort();
		}
	next:
		pthread_mutex_unlock(&stream->lock);
	}
}

static void destroy_channel_ht(struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *channel;
	int ret;

	if (ht == nullptr) {
		return;
	}

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ht->ht, &iter.iter, channel, wait_fd_node.node) {
			ret = lttng_ht_del(ht, &iter);
			LTTNG_ASSERT(ret != 0);
		}
	}

	lttng_ht_destroy(ht);
}

/*
 * This thread polls the channel fds to detect when they are being
 * closed. It closes all related streams if the channel is detected as
 * closed. It is currently only used as a shim layer for UST because the
 * consumerd needs to keep the per-stream wakeup end of pipes open for
 * periodical flush.
 */
void *consumer_thread_channel_poll(void *data)
{
	int ret, i, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_consumer_channel *chan = nullptr;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct lttng_poll_event events;
	struct lttng_consumer_local_data *ctx = (lttng_consumer_local_data *) data;
	struct lttng_ht *channel_ht;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_CHANNEL);

	if (testpoint(consumerd_thread_channel)) {
		goto error_testpoint;
	}

	health_code_update();

	channel_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!channel_ht) {
		/* ENOMEM at this point. Better to bail out. */
		goto end_ht;
	}

	DBG("Thread channel poll started");

	/* Size is set to 1 for the consumer_channel pipe */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		ERR("Poll set creation failed");
		goto end_poll;
	}

	ret = lttng_poll_add(&events, ctx->consumer_channel_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto end;
	}

	/* Main loop */
	DBG("Channel main loop started");

	while (true) {
	restart:
		health_code_update();
		DBG("Channel poll wait");
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG("Channel poll return from wait with %d fd(s)", LTTNG_POLL_GETNB(&events));
		health_poll_exit();
		DBG("Channel event caught in thread");
		if (ret < 0) {
			if (errno == EINTR) {
				ERR("Poll EINTR caught");
				goto restart;
			}
			if (LTTNG_POLL_GETNB(&events) == 0) {
				err = 0; /* All is OK */
			}
			goto end;
		}

		nb_fd = ret;

		/* From here, the event is a channel wait fd */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (pollfd == ctx->consumer_channel_pipe[0]) {
				if (revents & LPOLLIN) {
					enum consumer_channel_action action;
					uint64_t key;

					ret = read_channel_pipe(ctx, &chan, &key, &action);
					if (ret <= 0) {
						if (ret < 0) {
							ERR("Error reading channel pipe");
						}
						lttng_poll_del(&events,
							       ctx->consumer_channel_pipe[0]);
						continue;
					}

					switch (action) {
					case CONSUMER_CHANNEL_ADD:
					{
						DBG("Adding channel %d to poll set", chan->wait_fd);

						lttng_ht_node_init_u64(&chan->wait_fd_node,
								       chan->wait_fd);
						lttng::urcu::read_lock_guard read_lock;
						lttng_ht_add_unique_u64(channel_ht,
									&chan->wait_fd_node);
						/* Add channel to the global poll events list */
						// FIXME: Empty flag on a pipe pollset, this might
						// hang on FreeBSD.
						lttng_poll_add(&events, chan->wait_fd, 0);
						break;
					}
					case CONSUMER_CHANNEL_DEL:
					{
						/*
						 * This command should never be called if the
						 * channel has streams monitored by either the data
						 * or metadata thread. The consumer only notify this
						 * thread with a channel del. command if it receives
						 * a destroy channel command from the session daemon
						 * that send it if a command prior to the
						 * GET_CHANNEL failed.
						 */

						lttng::urcu::read_lock_guard read_lock;
						chan = consumer_find_channel(key);
						if (!chan) {
							ERR("UST consumer get channel key %" PRIu64
							    " not found for del channel",
							    key);
							break;
						}
						lttng_poll_del(&events, chan->wait_fd);
						iter.iter.node = &chan->wait_fd_node.node;
						ret = lttng_ht_del(channel_ht, &iter);
						LTTNG_ASSERT(ret == 0);

						switch (the_consumer_data.type) {
						case LTTNG_CONSUMER_KERNEL:
							break;
						case LTTNG_CONSUMER32_UST:
						case LTTNG_CONSUMER64_UST:
							health_code_update();
							/* Destroy streams that might have been left
							 * in the stream list. */
							clean_channel_stream_list(chan);
							break;
						default:
							ERR("Unknown consumer_data type");
							abort();
						}

						/*
						 * Release our own refcount. Force channel deletion
						 * even if streams were not initialized.
						 */
						if (!uatomic_sub_return(&chan->refcount, 1)) {
							consumer_del_channel(chan);
						}
						goto restart;
					}
					case CONSUMER_CHANNEL_QUIT:
						/*
						 * Remove the pipe from the poll set and continue
						 * the loop since their might be data to consume.
						 */
						lttng_poll_del(&events,
							       ctx->consumer_channel_pipe[0]);
						continue;
					default:
						ERR("Unknown action");
						break;
					}
				} else if (revents & (LPOLLERR | LPOLLHUP)) {
					DBG("Channel thread pipe hung up");
					/*
					 * Remove the pipe from the poll set and continue the loop
					 * since their might be data to consume.
					 */
					lttng_poll_del(&events, ctx->consumer_channel_pipe[0]);
					continue;
				} else {
					ERR("Unexpected poll events %u for sock %d",
					    revents,
					    pollfd);
					goto end;
				}

				/* Handle other stream */
				continue;
			}

			lttng::urcu::read_lock_guard read_lock;
			{
				uint64_t tmp_id = (uint64_t) pollfd;

				lttng_ht_lookup(channel_ht, &tmp_id, &iter);
			}
			node = lttng_ht_iter_get_node_u64(&iter);
			LTTNG_ASSERT(node);

			chan = caa_container_of(node, struct lttng_consumer_channel, wait_fd_node);

			/* Check for error event */
			if (revents & (LPOLLERR | LPOLLHUP)) {
				DBG("Channel fd %d is hup|err.", pollfd);

				lttng_poll_del(&events, chan->wait_fd);
				ret = lttng_ht_del(channel_ht, &iter);
				LTTNG_ASSERT(ret == 0);

				/*
				 * This will close the wait fd for each stream associated to
				 * this channel AND monitored by the data/metadata thread thus
				 * will be clean by the right thread.
				 */
				consumer_close_channel_streams(chan);

				/* Release our own refcount */
				if (!uatomic_sub_return(&chan->refcount, 1) &&
				    !uatomic_read(&chan->nb_init_stream_left)) {
					consumer_del_channel(chan);
				}
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto end;
			}

			/* Release RCU lock for the channel looked up */
		}
	}

	/* All is OK */
	err = 0;
end:
	lttng_poll_clean(&events);
end_poll:
	destroy_channel_ht(channel_ht);
end_ht:
error_testpoint:
	DBG("Channel poll thread exiting");
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_consumerd);
	rcu_unregister_thread();
	return nullptr;
}

static int set_metadata_socket(struct lttng_consumer_local_data *ctx,
			       struct pollfd *sockpoll,
			       int client_socket)
{
	int ret;

	LTTNG_ASSERT(ctx);
	LTTNG_ASSERT(sockpoll);

	ret = lttng_consumer_poll_socket(sockpoll);
	if (ret) {
		goto error;
	}
	DBG("Metadata connection on client_socket");

	/* Blocking call, waiting for transmission */
	ctx->consumer_metadata_socket = lttcomm_accept_unix_sock(client_socket);
	if (ctx->consumer_metadata_socket < 0) {
		WARN("On accept metadata");
		ret = -1;
		goto error;
	}
	ret = 0;

error:
	return ret;
}

/*
 * This thread listens on the consumerd socket and receives the file
 * descriptors from the session daemon.
 */
void *consumer_thread_sessiond_poll(void *data)
{
	int sock = -1, client_socket, ret, err = -1;
	/*
	 * structure to poll for incoming data on communication socket avoids
	 * making blocking sockets.
	 */
	struct pollfd consumer_sockpoll[2];
	struct lttng_consumer_local_data *ctx = (lttng_consumer_local_data *) data;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_SESSIOND);

	if (testpoint(consumerd_thread_sessiond)) {
		goto error_testpoint;
	}

	health_code_update();

	DBG("Creating command socket %s", ctx->consumer_command_sock_path);
	unlink(ctx->consumer_command_sock_path);
	client_socket = lttcomm_create_unix_sock(ctx->consumer_command_sock_path);
	if (client_socket < 0) {
		ERR("Cannot create command socket");
		goto end;
	}

	ret = lttcomm_listen_unix_sock(client_socket);
	if (ret < 0) {
		goto end;
	}

	DBG("Sending ready command to lttng-sessiond");
	ret = lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_COMMAND_SOCK_READY);
	/* return < 0 on error, but == 0 is not fatal */
	if (ret < 0) {
		ERR("Error sending ready command to lttng-sessiond");
		goto end;
	}

	/* prepare the FDs to poll : to client socket and the should_quit pipe */
	consumer_sockpoll[0].fd = ctx->consumer_should_quit[0];
	consumer_sockpoll[0].events = POLLIN | POLLPRI;
	consumer_sockpoll[1].fd = client_socket;
	consumer_sockpoll[1].events = POLLIN | POLLPRI;

	ret = lttng_consumer_poll_socket(consumer_sockpoll);
	if (ret) {
		if (ret > 0) {
			/* should exit */
			err = 0;
		}
		goto end;
	}
	DBG("Connection on client_socket");

	/* Blocking call, waiting for transmission */
	sock = lttcomm_accept_unix_sock(client_socket);
	if (sock < 0) {
		WARN("On accept");
		goto end;
	}

	/*
	 * Setup metadata socket which is the second socket connection on the
	 * command unix socket.
	 */
	ret = set_metadata_socket(ctx, consumer_sockpoll, client_socket);
	if (ret) {
		if (ret > 0) {
			/* should exit */
			err = 0;
		}
		goto end;
	}

	/* This socket is not useful anymore. */
	ret = close(client_socket);
	if (ret < 0) {
		PERROR("close client_socket");
	}
	client_socket = -1;

	/* update the polling structure to poll on the established socket */
	consumer_sockpoll[1].fd = sock;
	consumer_sockpoll[1].events = POLLIN | POLLPRI;

	while (true) {
		health_code_update();

		health_poll_entry();
		ret = lttng_consumer_poll_socket(consumer_sockpoll);
		health_poll_exit();
		if (ret) {
			if (ret > 0) {
				/* should exit */
				err = 0;
			}
			goto end;
		}
		DBG("Incoming command on sock");
		ret = lttng_consumer_recv_cmd(ctx, sock, consumer_sockpoll);
		if (ret <= 0) {
			/*
			 * This could simply be a session daemon quitting. Don't output
			 * ERR() here.
			 */
			DBG("Communication interrupted on command socket");
			err = 0;
			goto end;
		}
		if (CMM_LOAD_SHARED(consumer_quit)) {
			DBG("consumer_thread_receive_fds received quit from signal");
			err = 0; /* All is OK */
			goto end;
		}
		DBG("Received command on sock");
	}
	/* All is OK */
	err = 0;

end:
	DBG("Consumer thread sessiond poll exiting");

	/*
	 * Close metadata streams since the producer is the session daemon which
	 * just died.
	 *
	 * NOTE: for now, this only applies to the UST tracer.
	 */
	lttng_consumer_close_all_metadata();

	/*
	 * when all fds have hung up, the polling thread
	 * can exit cleanly
	 */
	CMM_STORE_SHARED(consumer_quit, 1);

	/*
	 * Notify the data poll thread to poll back again and test the
	 * consumer_quit state that we just set so to quit gracefully.
	 */
	notify_thread_lttng_pipe(ctx->consumer_data_pipe);

	notify_channel_pipe(ctx, nullptr, -1, CONSUMER_CHANNEL_QUIT);

	notify_health_quit_pipe(health_quit_pipe);

	/* Cleaning up possibly open sockets. */
	if (sock >= 0) {
		ret = close(sock);
		if (ret < 0) {
			PERROR("close sock sessiond poll");
		}
	}
	if (client_socket >= 0) {
		ret = close(client_socket);
		if (ret < 0) {
			PERROR("close client_socket sessiond poll");
		}
	}

error_testpoint:
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_consumerd);

	rcu_unregister_thread();
	return nullptr;
}

static int post_consume(struct lttng_consumer_stream *stream,
			const struct stream_subbuffer *subbuffer,
			struct lttng_consumer_local_data *ctx)
{
	size_t i;
	int ret = 0;
	const size_t count =
		lttng_dynamic_array_get_count(&stream->read_subbuffer_ops.post_consume_cbs);

	for (i = 0; i < count; i++) {
		const post_consume_cb op = *(post_consume_cb *) lttng_dynamic_array_get_element(
			&stream->read_subbuffer_ops.post_consume_cbs, i);

		ret = op(stream, subbuffer, ctx);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

ssize_t lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
				      struct lttng_consumer_local_data *ctx,
				      bool locked_by_caller)
{
	ssize_t ret, written_bytes = 0;
	int rotation_ret;
	struct stream_subbuffer subbuffer = {};
	enum get_next_subbuffer_status get_next_status;

	if (!locked_by_caller) {
		stream->read_subbuffer_ops.lock(stream);
	} else {
		stream->read_subbuffer_ops.assert_locked(stream);
	}

	if (stream->read_subbuffer_ops.on_wake_up) {
		ret = stream->read_subbuffer_ops.on_wake_up(stream);
		if (ret) {
			goto end;
		}
	}

	/*
	 * If the stream was flagged to be ready for rotation before we extract
	 * the next packet, rotate it now.
	 */
	if (stream->rotate_ready) {
		DBG("Rotate stream before consuming data");
		ret = lttng_consumer_rotate_stream(stream);
		if (ret < 0) {
			ERR("Stream rotation error before consuming data");
			goto end;
		}
	}

	get_next_status = stream->read_subbuffer_ops.get_next_subbuffer(stream, &subbuffer);
	switch (get_next_status) {
	case GET_NEXT_SUBBUFFER_STATUS_OK:
		break;
	case GET_NEXT_SUBBUFFER_STATUS_NO_DATA:
		/* Not an error. */
		ret = 0;
		goto sleep_stream;
	case GET_NEXT_SUBBUFFER_STATUS_ERROR:
		ret = -1;
		goto end;
	default:
		abort();
	}

	ret = stream->read_subbuffer_ops.pre_consume_subbuffer(stream, &subbuffer);
	if (ret) {
		goto error_put_subbuf;
	}

	written_bytes = stream->read_subbuffer_ops.consume_subbuffer(ctx, stream, &subbuffer);
	if (written_bytes <= 0) {
		ERR("Error consuming subbuffer: (%zd)", written_bytes);
		ret = (int) written_bytes;
		goto error_put_subbuf;
	}

	ret = stream->read_subbuffer_ops.put_next_subbuffer(stream, &subbuffer);
	if (ret) {
		goto end;
	}

	ret = post_consume(stream, &subbuffer, ctx);
	if (ret) {
		goto end;
	}

	/*
	 * After extracting the packet, we check if the stream is now ready to
	 * be rotated and perform the action immediately.
	 *
	 * Don't overwrite `ret` as callers expect the number of bytes
	 * consumed to be returned on success.
	 */
	rotation_ret = lttng_consumer_stream_is_rotate_ready(stream);
	if (rotation_ret == 1) {
		rotation_ret = lttng_consumer_rotate_stream(stream);
		if (rotation_ret < 0) {
			ret = rotation_ret;
			ERR("Stream rotation error after consuming data");
			goto end;
		}

	} else if (rotation_ret < 0) {
		ret = rotation_ret;
		ERR("Failed to check if stream was ready to rotate after consuming data");
		goto end;
	}

sleep_stream:
	if (stream->read_subbuffer_ops.on_sleep) {
		stream->read_subbuffer_ops.on_sleep(stream, ctx);
	}

	ret = written_bytes;
end:
	if (!locked_by_caller) {
		stream->read_subbuffer_ops.unlock(stream);
	}

	return ret;
error_put_subbuf:
	(void) stream->read_subbuffer_ops.put_next_subbuffer(stream, &subbuffer);
	goto end;
}

int lttng_consumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_on_recv_stream(stream);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_on_recv_stream(stream);
	default:
		ERR("Unknown consumer_data type");
		abort();
		return -ENOSYS;
	}
}

/*
 * Allocate and set consumer data hash tables.
 */
int lttng_consumer_init()
{
	the_consumer_data.channel_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!the_consumer_data.channel_ht) {
		goto error;
	}

	the_consumer_data.channels_by_session_id_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!the_consumer_data.channels_by_session_id_ht) {
		goto error;
	}

	the_consumer_data.relayd_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!the_consumer_data.relayd_ht) {
		goto error;
	}

	the_consumer_data.stream_list_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!the_consumer_data.stream_list_ht) {
		goto error;
	}

	the_consumer_data.stream_per_chan_id_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!the_consumer_data.stream_per_chan_id_ht) {
		goto error;
	}

	data_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!data_ht) {
		goto error;
	}

	metadata_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!metadata_ht) {
		goto error;
	}

	the_consumer_data.chunk_registry = lttng_trace_chunk_registry_create();
	if (!the_consumer_data.chunk_registry) {
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Process the ADD_RELAYD command receive by a consumer.
 *
 * This will create a relayd socket pair and add it to the relayd hash table.
 * The caller MUST acquire a RCU read side lock before calling it.
 */
void consumer_add_relayd_socket(uint64_t net_seq_idx,
				int sock_type,
				struct lttng_consumer_local_data *ctx,
				int sock,
				struct pollfd *consumer_sockpoll,
				uint64_t sessiond_id,
				uint64_t relayd_session_id,
				uint32_t relayd_version_major,
				uint32_t relayd_version_minor,
				enum lttcomm_sock_proto relayd_socket_protocol)
{
	int fd = -1, ret = -1, relayd_created = 0;
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct consumer_relayd_sock_pair *relayd = nullptr;

	LTTNG_ASSERT(ctx);
	LTTNG_ASSERT(sock >= 0);
	ASSERT_RCU_READ_LOCKED();

	DBG("Consumer adding relayd socket (idx: %" PRIu64 ")", net_seq_idx);

	/* Get relayd reference if exists. */
	relayd = consumer_find_relayd(net_seq_idx);
	if (relayd == nullptr) {
		LTTNG_ASSERT(sock_type == LTTNG_STREAM_CONTROL);
		/* Not found. Allocate one. */
		relayd = consumer_allocate_relayd_sock_pair(net_seq_idx);
		if (relayd == nullptr) {
			ret_code = LTTCOMM_CONSUMERD_ENOMEM;
			goto error;
		} else {
			relayd->sessiond_session_id = sessiond_id;
			relayd_created = 1;
		}

		/*
		 * This code path MUST continue to the consumer send status message to
		 * we can notify the session daemon and continue our work without
		 * killing everything.
		 */
	} else {
		/*
		 * relayd key should never be found for control socket.
		 */
		LTTNG_ASSERT(sock_type != LTTNG_STREAM_CONTROL);
	}

	/* First send a status message before receiving the fds. */
	ret = consumer_send_status_msg(sock, LTTCOMM_CONSUMERD_SUCCESS);
	if (ret < 0) {
		/* Somehow, the session daemon is not responding anymore. */
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_FATAL);
		goto error_nosignal;
	}

	/* Poll on consumer socket. */
	ret = lttng_consumer_poll_socket(consumer_sockpoll);
	if (ret) {
		/* Needing to exit in the middle of a command: error. */
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_POLL_ERROR);
		goto error_nosignal;
	}

	/* Get relayd socket from session daemon */
	ret = lttcomm_recv_fds_unix_sock(sock, &fd, 1);
	if (ret != sizeof(fd)) {
		fd = -1; /* Just in case it gets set with an invalid value. */

		/*
		 * Failing to receive FDs might indicate a major problem such as
		 * reaching a fd limit during the receive where the kernel returns a
		 * MSG_CTRUNC and fails to cleanup the fd in the queue. Any case, we
		 * don't take any chances and stop everything.
		 *
		 * XXX: Feature request #558 will fix that and avoid this possible
		 * issue when reaching the fd limit.
		 */
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
		ret_code = LTTCOMM_CONSUMERD_ERROR_RECV_FD;
		goto error;
	}

	/* Copy socket information and received FD */
	switch (sock_type) {
	case LTTNG_STREAM_CONTROL:
		/* Copy received lttcomm socket */
		ret = lttcomm_populate_sock_from_open_socket(
			&relayd->control_sock.sock, fd, relayd_socket_protocol);

		/* Assign version values. */
		relayd->control_sock.major = relayd_version_major;
		relayd->control_sock.minor = relayd_version_minor;

		relayd->relayd_session_id = relayd_session_id;

		break;
	case LTTNG_STREAM_DATA:
		/* Copy received lttcomm socket */
		ret = lttcomm_populate_sock_from_open_socket(
			&relayd->data_sock.sock, fd, relayd_socket_protocol);
		/* Assign version values. */
		relayd->data_sock.major = relayd_version_major;
		relayd->data_sock.minor = relayd_version_minor;
		break;
	default:
		ERR("Unknown relayd socket type (%d)", sock_type);
		ret_code = LTTCOMM_CONSUMERD_FATAL;
		goto error;
	}

	if (ret < 0) {
		ret_code = LTTCOMM_CONSUMERD_FATAL;
		goto error;
	}

	DBG("Consumer %s socket created successfully with net idx %" PRIu64 " (fd: %d)",
	    sock_type == LTTNG_STREAM_CONTROL ? "control" : "data",
	    relayd->net_seq_idx,
	    fd);
	/*
	 * We gave the ownership of the fd to the relayd structure. Set the
	 * fd to -1 so we don't call close() on it in the error path below.
	 */
	fd = -1;

	/* We successfully added the socket. Send status back. */
	ret = consumer_send_status_msg(sock, ret_code);
	if (ret < 0) {
		/* Somehow, the session daemon is not responding anymore. */
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_FATAL);
		goto error_nosignal;
	}

	/*
	 * Add relayd socket pair to consumer data hashtable. If object already
	 * exists or on error, the function gracefully returns.
	 */
	relayd->ctx = ctx;
	add_relayd(relayd);

	/* All good! */
	return;

error:
	if (consumer_send_status_msg(sock, ret_code) < 0) {
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_FATAL);
	}

error_nosignal:
	/* Close received socket if valid. */
	if (fd >= 0) {
		if (close(fd)) {
			PERROR("close received socket");
		}
	}

	if (relayd_created) {
		free(relayd);
	}
}

/*
 * Search for a relayd associated to the session id and return the reference.
 *
 * A rcu read side lock MUST be acquire before calling this function and locked
 * until the relayd object is no longer necessary.
 */
static struct consumer_relayd_sock_pair *find_relayd_by_session_id(uint64_t id)
{
	struct lttng_ht_iter iter;
	struct consumer_relayd_sock_pair *relayd = nullptr;

	ASSERT_RCU_READ_LOCKED();

	/* Iterate over all relayd since they are indexed by net_seq_idx. */
	cds_lfht_for_each_entry (the_consumer_data.relayd_ht->ht, &iter.iter, relayd, node.node) {
		/*
		 * Check by sessiond id which is unique here where the relayd session
		 * id might not be when having multiple relayd.
		 */
		if (relayd->sessiond_session_id == id) {
			/* Found the relayd. There can be only one per id. */
			goto found;
		}
	}

	return nullptr;

found:
	return relayd;
}

/*
 * Check if for a given session id there is still data needed to be extract
 * from the buffers.
 *
 * Return 1 if data is pending or else 0 meaning ready to be read.
 */
int consumer_data_pending(uint64_t id)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht;
	struct lttng_consumer_stream *stream;
	struct consumer_relayd_sock_pair *relayd = nullptr;
	int (*data_pending)(struct lttng_consumer_stream *);

	DBG("Consumer data pending command on session id %" PRIu64, id);

	lttng::urcu::read_lock_guard read_lock;
	pthread_mutex_lock(&the_consumer_data.lock);

	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		data_pending = lttng_kconsumer_data_pending;
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		data_pending = lttng_ustconsumer_data_pending;
		break;
	default:
		ERR("Unknown consumer data type");
		abort();
	}

	/* Ease our life a bit */
	ht = the_consumer_data.stream_list_ht;

	cds_lfht_for_each_entry_duplicate(ht->ht,
					  ht->hash_fct(&id, lttng_ht_seed),
					  ht->match_fct,
					  &id,
					  &iter.iter,
					  stream,
					  node_session_id.node)
	{
		pthread_mutex_lock(&stream->lock);

		/*
		 * A removed node from the hash table indicates that the stream has
		 * been deleted thus having a guarantee that the buffers are closed
		 * on the consumer side. However, data can still be transmitted
		 * over the network so don't skip the relayd check.
		 */
		ret = cds_lfht_is_node_deleted(&stream->node.node);
		if (!ret) {
			/* Check the stream if there is data in the buffers. */
			ret = data_pending(stream);
			if (ret == 1) {
				pthread_mutex_unlock(&stream->lock);
				goto data_pending;
			}
		}

		pthread_mutex_unlock(&stream->lock);
	}

	relayd = find_relayd_by_session_id(id);
	if (relayd) {
		unsigned int is_data_inflight = 0;

		/* Send init command for data pending. */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_begin_data_pending(&relayd->control_sock, relayd->relayd_session_id);
		if (ret < 0) {
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
			/* Communication error thus the relayd so no data pending. */
			goto data_not_pending;
		}

		cds_lfht_for_each_entry_duplicate(ht->ht,
						  ht->hash_fct(&id, lttng_ht_seed),
						  ht->match_fct,
						  &id,
						  &iter.iter,
						  stream,
						  node_session_id.node)
		{
			if (stream->metadata_flag) {
				ret = relayd_quiescent_control(&relayd->control_sock,
							       stream->relayd_stream_id);
			} else {
				ret = relayd_data_pending(&relayd->control_sock,
							  stream->relayd_stream_id,
							  stream->next_net_seq_num - 1);
			}

			if (ret == 1) {
				pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
				goto data_pending;
			} else if (ret < 0) {
				ERR("Relayd data pending failed. Cleaning up relayd %" PRIu64 ".",
				    relayd->net_seq_idx);
				lttng_consumer_cleanup_relayd(relayd);
				pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
				goto data_not_pending;
			}
		}

		/* Send end command for data pending. */
		ret = relayd_end_data_pending(
			&relayd->control_sock, relayd->relayd_session_id, &is_data_inflight);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
			ERR("Relayd end data pending failed. Cleaning up relayd %" PRIu64 ".",
			    relayd->net_seq_idx);
			lttng_consumer_cleanup_relayd(relayd);
			goto data_not_pending;
		}
		if (is_data_inflight) {
			goto data_pending;
		}
	}

	/*
	 * Finding _no_ node in the hash table and no inflight data means that the
	 * stream(s) have been removed thus data is guaranteed to be available for
	 * analysis from the trace files.
	 */

data_not_pending:
	/* Data is available to be read by a viewer. */
	pthread_mutex_unlock(&the_consumer_data.lock);
	return 0;

data_pending:
	/* Data is still being extracted from buffers. */
	pthread_mutex_unlock(&the_consumer_data.lock);
	return 1;
}

/*
 * Send a ret code status message to the sessiond daemon.
 *
 * Return the sendmsg() return value.
 */
int consumer_send_status_msg(int sock, int ret_code)
{
	struct lttcomm_consumer_status_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.ret_code = (lttcomm_return_code) ret_code;

	return lttcomm_send_unix_sock(sock, &msg, sizeof(msg));
}

/*
 * Send a channel status message to the sessiond daemon.
 *
 * Return the sendmsg() return value.
 */
int consumer_send_status_channel(int sock, struct lttng_consumer_channel *channel)
{
	struct lttcomm_consumer_status_channel msg;

	LTTNG_ASSERT(sock >= 0);

	memset(&msg, 0, sizeof(msg));
	if (!channel) {
		msg.ret_code = LTTCOMM_CONSUMERD_CHANNEL_FAIL;
	} else {
		msg.ret_code = LTTCOMM_CONSUMERD_SUCCESS;
		msg.key = channel->key;
		msg.stream_count = channel->streams.count;
	}

	return lttcomm_send_unix_sock(sock, &msg, sizeof(msg));
}

unsigned long consumer_get_consume_start_pos(unsigned long consumed_pos,
					     unsigned long produced_pos,
					     uint64_t nb_packets_per_stream,
					     uint64_t max_sb_size)
{
	unsigned long start_pos;

	if (!nb_packets_per_stream) {
		return consumed_pos; /* Grab everything */
	}
	start_pos = produced_pos - lttng_offset_align_floor(produced_pos, max_sb_size);
	start_pos -= max_sb_size * nb_packets_per_stream;
	if ((long) (start_pos - consumed_pos) < 0) {
		return consumed_pos; /* Grab everything */
	}
	return start_pos;
}

/* Stream lock must be held by the caller. */
static int sample_stream_positions(struct lttng_consumer_stream *stream,
				   unsigned long *produced,
				   unsigned long *consumed)
{
	int ret;

	ASSERT_LOCKED(stream->lock);

	ret = lttng_consumer_sample_snapshot_positions(stream);
	if (ret < 0) {
		ERR("Failed to sample snapshot positions");
		goto end;
	}

	ret = lttng_consumer_get_produced_snapshot(stream, produced);
	if (ret < 0) {
		ERR("Failed to sample produced position");
		goto end;
	}

	ret = lttng_consumer_get_consumed_snapshot(stream, consumed);
	if (ret < 0) {
		ERR("Failed to sample consumed position");
		goto end;
	}

end:
	return ret;
}

/*
 * Sample the rotate position for all the streams of a channel. If a stream
 * is already at the rotate position (produced == consumed), we flag it as
 * ready for rotation. The rotation of ready streams occurs after we have
 * replied to the session daemon that we have finished sampling the positions.
 * Must be called with RCU read-side lock held to ensure existence of channel.
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_rotate_channel(struct lttng_consumer_channel *channel,
				  uint64_t key,
				  uint64_t relayd_id)
{
	int ret;
	struct lttng_consumer_stream *stream;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht = the_consumer_data.stream_per_chan_id_ht;
	struct lttng_dynamic_array stream_rotation_positions;
	uint64_t next_chunk_id, stream_count = 0;
	enum lttng_trace_chunk_status chunk_status;
	const bool is_local_trace = relayd_id == -1ULL;
	struct consumer_relayd_sock_pair *relayd = nullptr;
	bool rotating_to_new_chunk = true;
	/* Array of `struct lttng_consumer_stream *` */
	struct lttng_dynamic_pointer_array streams_packet_to_open;
	size_t stream_idx;

	ASSERT_RCU_READ_LOCKED();

	DBG("Consumer sample rotate position for channel %" PRIu64, key);

	lttng_dynamic_array_init(&stream_rotation_positions,
				 sizeof(struct relayd_stream_rotation_position),
				 nullptr);
	lttng_dynamic_pointer_array_init(&streams_packet_to_open, nullptr);

	lttng::urcu::read_lock_guard read_lock;

	pthread_mutex_lock(&channel->lock);
	LTTNG_ASSERT(channel->trace_chunk);
	chunk_status = lttng_trace_chunk_get_id(channel->trace_chunk, &next_chunk_id);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end_unlock_channel;
	}

	cds_lfht_for_each_entry_duplicate(ht->ht,
					  ht->hash_fct(&channel->key, lttng_ht_seed),
					  ht->match_fct,
					  &channel->key,
					  &iter.iter,
					  stream,
					  node_channel_id.node)
	{
		unsigned long produced_pos = 0, consumed_pos = 0;

		health_code_update();

		/*
		 * Lock stream because we are about to change its state.
		 */
		pthread_mutex_lock(&stream->lock);

		if (stream->trace_chunk == stream->chan->trace_chunk) {
			rotating_to_new_chunk = false;
		}

		/*
		 * Do not flush a packet when rotating from a NULL trace
		 * chunk. The stream has no means to output data, and the prior
		 * rotation which rotated to NULL performed that side-effect
		 * already. No new data can be produced when a stream has no
		 * associated trace chunk (e.g. a stop followed by a rotate).
		 */
		if (stream->trace_chunk) {
			bool flush_active;

			if (stream->metadata_flag) {
				/*
				 * Don't produce an empty metadata packet,
				 * simply close the current one.
				 *
				 * Metadata is regenerated on every trace chunk
				 * switch; there is no concern that no data was
				 * produced.
				 */
				flush_active = true;
			} else {
				/*
				 * Only flush an empty packet if the "packet
				 * open" could not be performed on transition
				 * to a new trace chunk and no packets were
				 * consumed within the chunk's lifetime.
				 */
				if (stream->opened_packet_in_current_trace_chunk) {
					flush_active = true;
				} else {
					/*
					 * Stream could have been full at the
					 * time of rotation, but then have had
					 * no activity at all.
					 *
					 * It is important to flush a packet
					 * to prevent 0-length files from being
					 * produced as most viewers choke on
					 * them.
					 *
					 * Unfortunately viewers will not be
					 * able to know that tracing was active
					 * for this stream during this trace
					 * chunk's lifetime.
					 */
					ret = sample_stream_positions(
						stream, &produced_pos, &consumed_pos);
					if (ret) {
						goto end_unlock_stream;
					}

					/*
					 * Don't flush an empty packet if data
					 * was produced; it will be consumed
					 * before the rotation completes.
					 */
					flush_active = produced_pos != consumed_pos;
					if (!flush_active) {
						const char *trace_chunk_name;
						uint64_t trace_chunk_id;

						chunk_status = lttng_trace_chunk_get_name(
							stream->trace_chunk,
							&trace_chunk_name,
							nullptr);
						if (chunk_status == LTTNG_TRACE_CHUNK_STATUS_NONE) {
							trace_chunk_name = "none";
						}

						/*
						 * Consumer trace chunks are
						 * never anonymous.
						 */
						chunk_status = lttng_trace_chunk_get_id(
							stream->trace_chunk, &trace_chunk_id);
						LTTNG_ASSERT(chunk_status ==
							     LTTNG_TRACE_CHUNK_STATUS_OK);

						DBG("Unable to open packet for stream during trace chunk's lifetime. "
						    "Flushing an empty packet to prevent an empty file from being created: "
						    "stream id = %" PRIu64
						    ", trace chunk name = `%s`, trace chunk id = %" PRIu64,
						    stream->key,
						    trace_chunk_name,
						    trace_chunk_id);
					}
				}
			}

			/*
			 * Close the current packet before sampling the
			 * ring buffer positions.
			 */
			ret = consumer_stream_flush_buffer(stream, flush_active);
			if (ret < 0) {
				ERR("Failed to flush stream %" PRIu64 " during channel rotation",
				    stream->key);
				goto end_unlock_stream;
			}
		}

		ret = lttng_consumer_take_snapshot(stream);
		if (ret < 0 && ret != -ENODATA && ret != -EAGAIN) {
			ERR("Failed to sample snapshot position during channel rotation");
			goto end_unlock_stream;
		}
		if (!ret) {
			ret = lttng_consumer_get_produced_snapshot(stream, &produced_pos);
			if (ret < 0) {
				ERR("Failed to sample produced position during channel rotation");
				goto end_unlock_stream;
			}

			ret = lttng_consumer_get_consumed_snapshot(stream, &consumed_pos);
			if (ret < 0) {
				ERR("Failed to sample consumed position during channel rotation");
				goto end_unlock_stream;
			}
		}
		/*
		 * Align produced position on the start-of-packet boundary of the first
		 * packet going into the next trace chunk.
		 */
		produced_pos = lttng_align_floor(produced_pos, stream->max_sb_size);
		if (consumed_pos == produced_pos) {
			DBG("Set rotate ready for stream %" PRIu64 " produced = %lu consumed = %lu",
			    stream->key,
			    produced_pos,
			    consumed_pos);
			stream->rotate_ready = true;
		} else {
			DBG("Different consumed and produced positions "
			    "for stream %" PRIu64 " produced = %lu consumed = %lu",
			    stream->key,
			    produced_pos,
			    consumed_pos);
		}
		/*
		 * The rotation position is based on the packet_seq_num of the
		 * packet following the last packet that was consumed for this
		 * stream, incremented by the offset between produced and
		 * consumed positions. This rotation position is a lower bound
		 * (inclusive) at which the next trace chunk starts. Since it
		 * is a lower bound, it is OK if the packet_seq_num does not
		 * correspond exactly to the same packet identified by the
		 * consumed_pos, which can happen in overwrite mode.
		 */
		if (stream->sequence_number_unavailable) {
			/*
			 * Rotation should never be performed on a session which
			 * interacts with a pre-2.8 lttng-modules, which does
			 * not implement packet sequence number.
			 */
			ERR("Failure to rotate stream %" PRIu64 ": sequence number unavailable",
			    stream->key);
			ret = -1;
			goto end_unlock_stream;
		}
		stream->rotate_position = stream->last_sequence_number + 1 +
			((produced_pos - consumed_pos) / stream->max_sb_size);
		DBG("Set rotation position for stream %" PRIu64 " at position %" PRIu64,
		    stream->key,
		    stream->rotate_position);

		if (!is_local_trace) {
			/*
			 * The relay daemon control protocol expects a rotation
			 * position as "the sequence number of the first packet
			 * _after_ the current trace chunk".
			 */
			const struct relayd_stream_rotation_position position = {
				.stream_id = stream->relayd_stream_id,
				.rotate_at_seq_num = stream->rotate_position,
			};

			ret = lttng_dynamic_array_add_element(&stream_rotation_positions,
							      &position);
			if (ret) {
				ERR("Failed to allocate stream rotation position");
				goto end_unlock_stream;
			}
			stream_count++;
		}

		stream->opened_packet_in_current_trace_chunk = false;

		if (rotating_to_new_chunk && !stream->metadata_flag) {
			/*
			 * Attempt to flush an empty packet as close to the
			 * rotation point as possible. In the event where a
			 * stream remains inactive after the rotation point,
			 * this ensures that the new trace chunk has a
			 * beginning timestamp set at the begining of the
			 * trace chunk instead of only creating an empty
			 * packet when the trace chunk is stopped.
			 *
			 * This indicates to the viewers that the stream
			 * was being recorded, but more importantly it
			 * allows viewers to determine a useable trace
			 * intersection.
			 *
			 * This presents a problem in the case where the
			 * ring-buffer is completely full.
			 *
			 * Consider the following scenario:
			 *   - The consumption of data is slow (slow network,
			 *     for instance),
			 *   - The ring buffer is full,
			 *   - A rotation is initiated,
			 *     - The flush below does nothing (no space left to
			 *       open a new packet),
			 *   - The other streams rotate very soon, and new
			 *     data is produced in the new chunk,
			 *   - This stream completes its rotation long after the
			 *     rotation was initiated
			 *   - The session is stopped before any event can be
			 *     produced	in this stream's buffers.
			 *
			 * The resulting trace chunk will have a single packet
			 * temporaly at the end of the trace chunk for this
			 * stream making the stream intersection more narrow
			 * than it should be.
			 *
			 * To work-around this, an empty flush is performed
			 * after the first consumption of a packet during a
			 * rotation if open_packet fails. The idea is that
			 * consuming a packet frees enough space to switch
			 * packets in this scenario and allows the tracer to
			 * "stamp" the beginning of the new trace chunk at the
			 * earliest possible point.
			 *
			 * The packet open is performed after the channel
			 * rotation to ensure that no attempt to open a packet
			 * is performed in a stream that has no active trace
			 * chunk.
			 */
			ret = lttng_dynamic_pointer_array_add_pointer(&streams_packet_to_open,
								      stream);
			if (ret) {
				PERROR("Failed to add a stream pointer to array of streams in which to open a packet");
				ret = -1;
				goto end_unlock_stream;
			}
		}

		pthread_mutex_unlock(&stream->lock);
	}
	stream = nullptr;

	if (!is_local_trace) {
		relayd = consumer_find_relayd(relayd_id);
		if (!relayd) {
			ERR("Failed to find relayd %" PRIu64, relayd_id);
			ret = -1;
			goto end_unlock_channel;
		}

		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_rotate_streams(&relayd->control_sock,
					    stream_count,
					    rotating_to_new_chunk ? &next_chunk_id : nullptr,
					    (const struct relayd_stream_rotation_position *)
						    stream_rotation_positions.buffer.data);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
			ERR("Relayd rotate stream failed. Cleaning up relayd %" PRIu64,
			    relayd->net_seq_idx);
			lttng_consumer_cleanup_relayd(relayd);
			goto end_unlock_channel;
		}
	}

	for (stream_idx = 0;
	     stream_idx < lttng_dynamic_pointer_array_get_count(&streams_packet_to_open);
	     stream_idx++) {
		enum consumer_stream_open_packet_status status;

		stream = (lttng_consumer_stream *) lttng_dynamic_pointer_array_get_pointer(
			&streams_packet_to_open, stream_idx);

		pthread_mutex_lock(&stream->lock);
		status = consumer_stream_open_packet(stream);
		pthread_mutex_unlock(&stream->lock);
		switch (status) {
		case CONSUMER_STREAM_OPEN_PACKET_STATUS_OPENED:
			DBG("Opened a packet after a rotation: stream id = %" PRIu64
			    ", channel name = %s, session id = %" PRIu64,
			    stream->key,
			    stream->chan->name,
			    stream->chan->session_id);
			break;
		case CONSUMER_STREAM_OPEN_PACKET_STATUS_NO_SPACE:
			/*
			 * Can't open a packet as there is no space left
			 * in the buffer. A new packet will be opened
			 * once one has been consumed.
			 */
			DBG("No space left to open a packet after a rotation: stream id = %" PRIu64
			    ", channel name = %s, session id = %" PRIu64,
			    stream->key,
			    stream->chan->name,
			    stream->chan->session_id);
			break;
		case CONSUMER_STREAM_OPEN_PACKET_STATUS_ERROR:
			/* Logged by callee. */
			ret = -1;
			goto end_unlock_channel;
		default:
			abort();
		}
	}

	pthread_mutex_unlock(&channel->lock);
	ret = 0;
	goto end;

end_unlock_stream:
	pthread_mutex_unlock(&stream->lock);
end_unlock_channel:
	pthread_mutex_unlock(&channel->lock);
end:
	lttng_dynamic_array_reset(&stream_rotation_positions);
	lttng_dynamic_pointer_array_reset(&streams_packet_to_open);
	return ret;
}

static int consumer_clear_buffer(struct lttng_consumer_stream *stream)
{
	int ret = 0;
	unsigned long consumed_pos_before, consumed_pos_after;

	ret = lttng_consumer_sample_snapshot_positions(stream);
	if (ret < 0) {
		ERR("Taking snapshot positions");
		goto end;
	}

	ret = lttng_consumer_get_consumed_snapshot(stream, &consumed_pos_before);
	if (ret < 0) {
		ERR("Consumed snapshot position");
		goto end;
	}

	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		ret = kernctl_buffer_clear(stream->wait_fd);
		if (ret < 0) {
			ERR("Failed to clear kernel stream (ret = %d)", ret);
			goto end;
		}
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		ret = lttng_ustconsumer_clear_buffer(stream);
		if (ret < 0) {
			ERR("Failed to clear ust stream (ret = %d)", ret);
			goto end;
		}
		break;
	default:
		ERR("Unknown consumer_data type");
		abort();
	}

	ret = lttng_consumer_sample_snapshot_positions(stream);
	if (ret < 0) {
		ERR("Taking snapshot positions");
		goto end;
	}
	ret = lttng_consumer_get_consumed_snapshot(stream, &consumed_pos_after);
	if (ret < 0) {
		ERR("Consumed snapshot position");
		goto end;
	}
	DBG("clear: before: %lu after: %lu", consumed_pos_before, consumed_pos_after);
end:
	return ret;
}

static int consumer_clear_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	ret = consumer_stream_flush_buffer(stream, true);
	if (ret < 0) {
		ERR("Failed to flush stream %" PRIu64 " during channel clear", stream->key);
		ret = LTTCOMM_CONSUMERD_FATAL;
		goto error;
	}

	ret = consumer_clear_buffer(stream);
	if (ret < 0) {
		ERR("Failed to clear stream %" PRIu64 " during channel clear", stream->key);
		ret = LTTCOMM_CONSUMERD_FATAL;
		goto error;
	}

	ret = LTTCOMM_CONSUMERD_SUCCESS;
error:
	return ret;
}

static int consumer_clear_unmonitored_channel(struct lttng_consumer_channel *channel)
{
	int ret;
	struct lttng_consumer_stream *stream;

	lttng::urcu::read_lock_guard read_lock;
	pthread_mutex_lock(&channel->lock);
	cds_list_for_each_entry (stream, &channel->streams.head, send_node) {
		health_code_update();
		pthread_mutex_lock(&stream->lock);
		ret = consumer_clear_stream(stream);
		if (ret) {
			goto error_unlock;
		}
		pthread_mutex_unlock(&stream->lock);
	}
	pthread_mutex_unlock(&channel->lock);
	return 0;

error_unlock:
	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&channel->lock);
	return ret;
}

/*
 * Check if a stream is ready to be rotated after extracting it.
 *
 * Return 1 if it is ready for rotation, 0 if it is not, a negative value on
 * error. Stream lock must be held.
 */
int lttng_consumer_stream_is_rotate_ready(struct lttng_consumer_stream *stream)
{
	DBG("Check is rotate ready for stream %" PRIu64 " ready %u rotate_position %" PRIu64
	    " last_sequence_number %" PRIu64,
	    stream->key,
	    stream->rotate_ready,
	    stream->rotate_position,
	    stream->last_sequence_number);
	if (stream->rotate_ready) {
		return 1;
	}

	/*
	 * If packet seq num is unavailable, it means we are interacting
	 * with a pre-2.8 lttng-modules which does not implement the
	 * sequence number. Rotation should never be used by sessiond in this
	 * scenario.
	 */
	if (stream->sequence_number_unavailable) {
		ERR("Internal error: rotation used on stream %" PRIu64
		    " with unavailable sequence number",
		    stream->key);
		return -1;
	}

	if (stream->rotate_position == -1ULL || stream->last_sequence_number == -1ULL) {
		return 0;
	}

	/*
	 * Rotate position not reached yet. The stream rotate position is
	 * the position of the next packet belonging to the next trace chunk,
	 * but consumerd considers rotation ready when reaching the last
	 * packet of the current chunk, hence the "rotate_position - 1".
	 */

	DBG("Check is rotate ready for stream %" PRIu64 " last_sequence_number %" PRIu64
	    " rotate_position %" PRIu64,
	    stream->key,
	    stream->last_sequence_number,
	    stream->rotate_position);
	if (stream->last_sequence_number >= stream->rotate_position - 1) {
		return 1;
	}

	return 0;
}

/*
 * Reset the state for a stream after a rotation occurred.
 */
void lttng_consumer_reset_stream_rotate_state(struct lttng_consumer_stream *stream)
{
	DBG("lttng_consumer_reset_stream_rotate_state for stream %" PRIu64, stream->key);
	stream->rotate_position = -1ULL;
	stream->rotate_ready = false;
}

/*
 * Perform the rotation a local stream file.
 */
static int rotate_local_stream(struct lttng_consumer_stream *stream)
{
	int ret = 0;

	DBG("Rotate local stream: stream key %" PRIu64 ", channel key %" PRIu64,
	    stream->key,
	    stream->chan->key);
	stream->tracefile_size_current = 0;
	stream->tracefile_count_current = 0;

	if (stream->out_fd >= 0) {
		ret = close(stream->out_fd);
		if (ret) {
			PERROR("Failed to close stream out_fd of channel \"%s\"",
			       stream->chan->name);
		}
		stream->out_fd = -1;
	}

	if (stream->index_file) {
		lttng_index_file_put(stream->index_file);
		stream->index_file = nullptr;
	}

	if (!stream->trace_chunk) {
		goto end;
	}

	ret = consumer_stream_create_output_files(stream, true);
end:
	return ret;
}

/*
 * Performs the stream rotation for the rotate session feature if needed.
 * It must be called with the channel and stream locks held.
 *
 * Return 0 on success, a negative number of error.
 */
int lttng_consumer_rotate_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	DBG("Consumer rotate stream %" PRIu64, stream->key);

	/*
	 * Update the stream's 'current' chunk to the session's (channel)
	 * now-current chunk.
	 */
	lttng_trace_chunk_put(stream->trace_chunk);
	if (stream->chan->trace_chunk == stream->trace_chunk) {
		/*
		 * A channel can be rotated and not have a "next" chunk
		 * to transition to. In that case, the channel's "current chunk"
		 * has not been closed yet, but it has not been updated to
		 * a "next" trace chunk either. Hence, the stream, like its
		 * parent channel, becomes part of no chunk and can't output
		 * anything until a new trace chunk is created.
		 */
		stream->trace_chunk = nullptr;
	} else if (stream->chan->trace_chunk && !lttng_trace_chunk_get(stream->chan->trace_chunk)) {
		ERR("Failed to acquire a reference to channel's trace chunk during stream rotation");
		ret = -1;
		goto error;
	} else {
		/*
		 * Update the stream's trace chunk to its parent channel's
		 * current trace chunk.
		 */
		stream->trace_chunk = stream->chan->trace_chunk;
	}

	if (stream->net_seq_idx == (uint64_t) -1ULL) {
		ret = rotate_local_stream(stream);
		if (ret < 0) {
			ERR("Failed to rotate stream, ret = %i", ret);
			goto error;
		}
	}

	if (stream->metadata_flag && stream->trace_chunk) {
		/*
		 * If the stream has transitioned to a new trace
		 * chunk, the metadata should be re-dumped to the
		 * newest chunk.
		 *
		 * However, it is possible for a stream to transition to
		 * a "no-chunk" state. This can happen if a rotation
		 * occurs on an inactive session. In such cases, the metadata
		 * regeneration will happen when the next trace chunk is
		 * created.
		 */
		ret = consumer_metadata_stream_dump(stream);
		if (ret) {
			goto error;
		}
	}
	lttng_consumer_reset_stream_rotate_state(stream);

	ret = 0;

error:
	return ret;
}

/*
 * Rotate all the ready streams now.
 *
 * This is especially important for low throughput streams that have already
 * been consumed, we cannot wait for their next packet to perform the
 * rotation.
 * Need to be called with RCU read-side lock held to ensure existence of
 * channel.
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_rotate_ready_streams(struct lttng_consumer_channel *channel, uint64_t key)
{
	int ret;
	struct lttng_consumer_stream *stream;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht = the_consumer_data.stream_per_chan_id_ht;

	ASSERT_RCU_READ_LOCKED();

	lttng::urcu::read_lock_guard read_lock;

	DBG("Consumer rotate ready streams in channel %" PRIu64, key);

	cds_lfht_for_each_entry_duplicate(ht->ht,
					  ht->hash_fct(&channel->key, lttng_ht_seed),
					  ht->match_fct,
					  &channel->key,
					  &iter.iter,
					  stream,
					  node_channel_id.node)
	{
		health_code_update();

		pthread_mutex_lock(&stream->chan->lock);
		pthread_mutex_lock(&stream->lock);

		if (!stream->rotate_ready) {
			pthread_mutex_unlock(&stream->lock);
			pthread_mutex_unlock(&stream->chan->lock);
			continue;
		}
		DBG("Consumer rotate ready stream %" PRIu64, stream->key);

		ret = lttng_consumer_rotate_stream(stream);
		pthread_mutex_unlock(&stream->lock);
		pthread_mutex_unlock(&stream->chan->lock);
		if (ret) {
			goto end;
		}
	}

	ret = 0;

end:
	return ret;
}

enum lttcomm_return_code lttng_consumer_init_command(struct lttng_consumer_local_data *ctx,
						     const lttng_uuid& sessiond_uuid)
{
	enum lttcomm_return_code ret;
	char uuid_str[LTTNG_UUID_STR_LEN];

	if (ctx->sessiond_uuid.is_set) {
		ret = LTTCOMM_CONSUMERD_ALREADY_SET;
		goto end;
	}

	ctx->sessiond_uuid.is_set = true;
	ctx->sessiond_uuid.value = sessiond_uuid;
	ret = LTTCOMM_CONSUMERD_SUCCESS;
	lttng_uuid_to_str(sessiond_uuid, uuid_str);
	DBG("Received session daemon UUID: %s", uuid_str);
end:
	return ret;
}

enum lttcomm_return_code
lttng_consumer_create_trace_chunk(const uint64_t *relayd_id,
				  uint64_t session_id,
				  uint64_t chunk_id,
				  time_t chunk_creation_timestamp,
				  const char *chunk_override_name,
				  const struct lttng_credentials *credentials,
				  struct lttng_directory_handle *chunk_directory_handle)
{
	int ret;
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct lttng_trace_chunk *created_chunk = nullptr, *published_chunk = nullptr;
	enum lttng_trace_chunk_status chunk_status;
	char relayd_id_buffer[MAX_INT_DEC_LEN(*relayd_id)];
	char creation_timestamp_buffer[ISO8601_STR_LEN];
	const char *relayd_id_str = "(none)";
	const char *creation_timestamp_str;
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *channel;

	if (relayd_id) {
		/* Only used for logging purposes. */
		ret = snprintf(relayd_id_buffer, sizeof(relayd_id_buffer), "%" PRIu64, *relayd_id);
		if (ret > 0 && ret < sizeof(relayd_id_buffer)) {
			relayd_id_str = relayd_id_buffer;
		} else {
			relayd_id_str = "(formatting error)";
		}
	}

	/* Local protocol error. */
	LTTNG_ASSERT(chunk_creation_timestamp);
	ret = time_to_iso8601_str(chunk_creation_timestamp,
				  creation_timestamp_buffer,
				  sizeof(creation_timestamp_buffer));
	creation_timestamp_str = !ret ? creation_timestamp_buffer : "(formatting error)";

	DBG("Consumer create trace chunk command: relay_id = %s"
	    ", session_id = %" PRIu64 ", chunk_id = %" PRIu64 ", chunk_override_name = %s"
	    ", chunk_creation_timestamp = %s",
	    relayd_id_str,
	    session_id,
	    chunk_id,
	    chunk_override_name ?: "(none)",
	    creation_timestamp_str);

	/*
	 * The trace chunk registry, as used by the consumer daemon, implicitly
	 * owns the trace chunks. This is only needed in the consumer since
	 * the consumer has no notion of a session beyond session IDs being
	 * used to identify other objects.
	 *
	 * The lttng_trace_chunk_registry_publish() call below provides a
	 * reference which is not released; it implicitly becomes the session
	 * daemon's reference to the chunk in the consumer daemon.
	 *
	 * The lifetime of trace chunks in the consumer daemon is managed by
	 * the session daemon through the LTTNG_CONSUMER_CREATE_TRACE_CHUNK
	 * and LTTNG_CONSUMER_DESTROY_TRACE_CHUNK commands.
	 */
	created_chunk = lttng_trace_chunk_create(chunk_id, chunk_creation_timestamp, nullptr);
	if (!created_chunk) {
		ERR("Failed to create trace chunk");
		ret_code = LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED;
		goto error;
	}

	if (chunk_override_name) {
		chunk_status = lttng_trace_chunk_override_name(created_chunk, chunk_override_name);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret_code = LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED;
			goto error;
		}
	}

	if (chunk_directory_handle) {
		chunk_status = lttng_trace_chunk_set_credentials(created_chunk, credentials);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Failed to set trace chunk credentials");
			ret_code = LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED;
			goto error;
		}
		/*
		 * The consumer daemon has no ownership of the chunk output
		 * directory.
		 */
		chunk_status = lttng_trace_chunk_set_as_user(created_chunk, chunk_directory_handle);
		chunk_directory_handle = nullptr;
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Failed to set trace chunk's directory handle");
			ret_code = LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED;
			goto error;
		}
	}

	published_chunk = lttng_trace_chunk_registry_publish_chunk(
		the_consumer_data.chunk_registry, session_id, created_chunk);
	lttng_trace_chunk_put(created_chunk);
	created_chunk = nullptr;
	if (!published_chunk) {
		ERR("Failed to publish trace chunk");
		ret_code = LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED;
		goto error;
	}

	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_for_each_entry_duplicate(
			the_consumer_data.channels_by_session_id_ht->ht,
			the_consumer_data.channels_by_session_id_ht->hash_fct(&session_id,
									      lttng_ht_seed),
			the_consumer_data.channels_by_session_id_ht->match_fct,
			&session_id,
			&iter.iter,
			channel,
			channels_by_session_id_ht_node.node)
		{
			ret = lttng_consumer_channel_set_trace_chunk(channel, published_chunk);
			if (ret) {
				/*
				 * Roll-back the creation of this chunk.
				 *
				 * This is important since the session daemon will
				 * assume that the creation of this chunk failed and
				 * will never ask for it to be closed, resulting
				 * in a leak and an inconsistent state for some
				 * channels.
				 */
				enum lttcomm_return_code close_ret;
				char path[LTTNG_PATH_MAX];

				DBG("Failed to set new trace chunk on existing channels, rolling back");
				close_ret =
					lttng_consumer_close_trace_chunk(relayd_id,
									 session_id,
									 chunk_id,
									 chunk_creation_timestamp,
									 nullptr,
									 path);
				if (close_ret != LTTCOMM_CONSUMERD_SUCCESS) {
					ERR("Failed to roll-back the creation of new chunk: session_id = %" PRIu64
					    ", chunk_id = %" PRIu64,
					    session_id,
					    chunk_id);
				}

				ret_code = LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED;
				break;
			}
		}
	}

	if (relayd_id) {
		struct consumer_relayd_sock_pair *relayd;

		relayd = consumer_find_relayd(*relayd_id);
		if (relayd) {
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			ret = relayd_create_trace_chunk(&relayd->control_sock, published_chunk);
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		} else {
			ERR("Failed to find relay daemon socket: relayd_id = %" PRIu64, *relayd_id);
		}

		if (!relayd || ret) {
			enum lttcomm_return_code close_ret;
			char path[LTTNG_PATH_MAX];

			close_ret = lttng_consumer_close_trace_chunk(relayd_id,
								     session_id,
								     chunk_id,
								     chunk_creation_timestamp,
								     nullptr,
								     path);
			if (close_ret != LTTCOMM_CONSUMERD_SUCCESS) {
				ERR("Failed to roll-back the creation of new chunk: session_id = %" PRIu64
				    ", chunk_id = %" PRIu64,
				    session_id,
				    chunk_id);
			}

			ret_code = LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED;
			goto error_unlock;
		}
	}
error_unlock:
error:
	/* Release the reference returned by the "publish" operation. */
	lttng_trace_chunk_put(published_chunk);
	lttng_trace_chunk_put(created_chunk);
	return ret_code;
}

enum lttcomm_return_code
lttng_consumer_close_trace_chunk(const uint64_t *relayd_id,
				 uint64_t session_id,
				 uint64_t chunk_id,
				 time_t chunk_close_timestamp,
				 const enum lttng_trace_chunk_command_type *close_command,
				 char *path)
{
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct lttng_trace_chunk *chunk;
	char relayd_id_buffer[MAX_INT_DEC_LEN(*relayd_id)];
	const char *relayd_id_str = "(none)";
	const char *close_command_name = "none";
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *channel;
	enum lttng_trace_chunk_status chunk_status;

	if (relayd_id) {
		int ret;

		/* Only used for logging purposes. */
		ret = snprintf(relayd_id_buffer, sizeof(relayd_id_buffer), "%" PRIu64, *relayd_id);
		if (ret > 0 && ret < sizeof(relayd_id_buffer)) {
			relayd_id_str = relayd_id_buffer;
		} else {
			relayd_id_str = "(formatting error)";
		}
	}
	if (close_command) {
		close_command_name = lttng_trace_chunk_command_type_get_name(*close_command);
	}

	DBG("Consumer close trace chunk command: relayd_id = %s"
	    ", session_id = %" PRIu64 ", chunk_id = %" PRIu64 ", close command = %s",
	    relayd_id_str,
	    session_id,
	    chunk_id,
	    close_command_name);

	chunk = lttng_trace_chunk_registry_find_chunk(
		the_consumer_data.chunk_registry, session_id, chunk_id);
	if (!chunk) {
		ERR("Failed to find chunk: session_id = %" PRIu64 ", chunk_id = %" PRIu64,
		    session_id,
		    chunk_id);
		ret_code = LTTCOMM_CONSUMERD_UNKNOWN_TRACE_CHUNK;
		goto end;
	}

	chunk_status = lttng_trace_chunk_set_close_timestamp(chunk, chunk_close_timestamp);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret_code = LTTCOMM_CONSUMERD_CLOSE_TRACE_CHUNK_FAILED;
		goto end;
	}

	if (close_command) {
		chunk_status = lttng_trace_chunk_set_close_command(chunk, *close_command);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret_code = LTTCOMM_CONSUMERD_CLOSE_TRACE_CHUNK_FAILED;
			goto end;
		}
	}

	/*
	 * chunk is now invalid to access as we no longer hold a reference to
	 * it; it is only kept around to compare it (by address) to the
	 * current chunk found in the session's channels.
	 */
	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_for_each_entry (
			the_consumer_data.channel_ht->ht, &iter.iter, channel, node.node) {
			int ret;

			/*
			 * Only change the channel's chunk to NULL if it still
			 * references the chunk being closed. The channel may
			 * reference a newer channel in the case of a session
			 * rotation. When a session rotation occurs, the "next"
			 * chunk is created before the "current" chunk is closed.
			 */
			if (channel->trace_chunk != chunk) {
				continue;
			}
			ret = lttng_consumer_channel_set_trace_chunk(channel, nullptr);
			if (ret) {
				/*
				 * Attempt to close the chunk on as many channels as
				 * possible.
				 */
				ret_code = LTTCOMM_CONSUMERD_CLOSE_TRACE_CHUNK_FAILED;
			}
		}
	}
	if (relayd_id) {
		int ret;
		struct consumer_relayd_sock_pair *relayd;

		relayd = consumer_find_relayd(*relayd_id);
		if (relayd) {
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			ret = relayd_close_trace_chunk(&relayd->control_sock, chunk, path);
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		} else {
			ERR("Failed to find relay daemon socket: relayd_id = %" PRIu64, *relayd_id);
		}

		if (!relayd || ret) {
			ret_code = LTTCOMM_CONSUMERD_CLOSE_TRACE_CHUNK_FAILED;
			goto error_unlock;
		}
	}
error_unlock:
end:
	/*
	 * Release the reference returned by the "find" operation and
	 * the session daemon's implicit reference to the chunk.
	 */
	lttng_trace_chunk_put(chunk);
	lttng_trace_chunk_put(chunk);

	return ret_code;
}

enum lttcomm_return_code
lttng_consumer_trace_chunk_exists(const uint64_t *relayd_id, uint64_t session_id, uint64_t chunk_id)
{
	int ret;
	enum lttcomm_return_code ret_code;
	char relayd_id_buffer[MAX_INT_DEC_LEN(*relayd_id)];
	const char *relayd_id_str = "(none)";
	const bool is_local_trace = !relayd_id;
	struct consumer_relayd_sock_pair *relayd = nullptr;
	bool chunk_exists_local, chunk_exists_remote;
	lttng::urcu::read_lock_guard read_lock;

	if (relayd_id) {
		/* Only used for logging purposes. */
		ret = snprintf(relayd_id_buffer, sizeof(relayd_id_buffer), "%" PRIu64, *relayd_id);
		if (ret > 0 && ret < sizeof(relayd_id_buffer)) {
			relayd_id_str = relayd_id_buffer;
		} else {
			relayd_id_str = "(formatting error)";
		}
	}

	DBG("Consumer trace chunk exists command: relayd_id = %s"
	    ", chunk_id = %" PRIu64,
	    relayd_id_str,
	    chunk_id);
	ret = lttng_trace_chunk_registry_chunk_exists(
		the_consumer_data.chunk_registry, session_id, chunk_id, &chunk_exists_local);
	if (ret) {
		/* Internal error. */
		ERR("Failed to query the existence of a trace chunk");
		ret_code = LTTCOMM_CONSUMERD_FATAL;
		goto end;
	}
	DBG("Trace chunk %s locally", chunk_exists_local ? "exists" : "does not exist");
	if (chunk_exists_local) {
		ret_code = LTTCOMM_CONSUMERD_TRACE_CHUNK_EXISTS_LOCAL;
		goto end;
	} else if (is_local_trace) {
		ret_code = LTTCOMM_CONSUMERD_UNKNOWN_TRACE_CHUNK;
		goto end;
	}

	relayd = consumer_find_relayd(*relayd_id);
	if (!relayd) {
		ERR("Failed to find relayd %" PRIu64, *relayd_id);
		ret_code = LTTCOMM_CONSUMERD_INVALID_PARAMETERS;
		goto end_rcu_unlock;
	}
	DBG("Looking up existence of trace chunk on relay daemon");
	pthread_mutex_lock(&relayd->ctrl_sock_mutex);
	ret = relayd_trace_chunk_exists(&relayd->control_sock, chunk_id, &chunk_exists_remote);
	pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	if (ret < 0) {
		ERR("Failed to look-up the existence of trace chunk on relay daemon");
		ret_code = LTTCOMM_CONSUMERD_RELAYD_FAIL;
		goto end_rcu_unlock;
	}

	ret_code = chunk_exists_remote ? LTTCOMM_CONSUMERD_TRACE_CHUNK_EXISTS_REMOTE :
					 LTTCOMM_CONSUMERD_UNKNOWN_TRACE_CHUNK;
	DBG("Trace chunk %s on relay daemon", chunk_exists_remote ? "exists" : "does not exist");

end_rcu_unlock:
end:
	return ret_code;
}

static int consumer_clear_monitored_channel(struct lttng_consumer_channel *channel)
{
	struct lttng_ht *ht;
	struct lttng_consumer_stream *stream;
	struct lttng_ht_iter iter;
	int ret;

	ht = the_consumer_data.stream_per_chan_id_ht;

	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_for_each_entry_duplicate(ht->ht,
					  ht->hash_fct(&channel->key, lttng_ht_seed),
					  ht->match_fct,
					  &channel->key,
					  &iter.iter,
					  stream,
					  node_channel_id.node)
	{
		/*
		 * Protect against teardown with mutex.
		 */
		pthread_mutex_lock(&stream->lock);
		if (cds_lfht_is_node_deleted(&stream->node.node)) {
			goto next;
		}
		ret = consumer_clear_stream(stream);
		if (ret) {
			goto error_unlock;
		}
	next:
		pthread_mutex_unlock(&stream->lock);
	}
	return LTTCOMM_CONSUMERD_SUCCESS;

error_unlock:
	pthread_mutex_unlock(&stream->lock);
	return ret;
}

int lttng_consumer_clear_channel(struct lttng_consumer_channel *channel)
{
	int ret;

	DBG("Consumer clear channel %" PRIu64, channel->key);

	if (channel->type == CONSUMER_CHANNEL_TYPE_METADATA) {
		/*
		 * Nothing to do for the metadata channel/stream.
		 * Snapshot mechanism already take care of the metadata
		 * handling/generation, and monitored channels only need to
		 * have their data stream cleared..
		 */
		ret = LTTCOMM_CONSUMERD_SUCCESS;
		goto end;
	}

	if (!channel->monitor) {
		ret = consumer_clear_unmonitored_channel(channel);
	} else {
		ret = consumer_clear_monitored_channel(channel);
	}
end:
	return ret;
}

enum lttcomm_return_code lttng_consumer_open_channel_packets(struct lttng_consumer_channel *channel)
{
	struct lttng_consumer_stream *stream;
	enum lttcomm_return_code ret = LTTCOMM_CONSUMERD_SUCCESS;

	if (channel->metadata_stream) {
		ERR("Open channel packets command attempted on a metadata channel");
		ret = LTTCOMM_CONSUMERD_INVALID_PARAMETERS;
		goto end;
	}

	{
		lttng::urcu::read_lock_guard read_lock;
		cds_list_for_each_entry (stream, &channel->streams.head, send_node) {
			enum consumer_stream_open_packet_status status;

			pthread_mutex_lock(&stream->lock);
			if (cds_lfht_is_node_deleted(&stream->node.node)) {
				goto next;
			}

			status = consumer_stream_open_packet(stream);
			switch (status) {
			case CONSUMER_STREAM_OPEN_PACKET_STATUS_OPENED:
				DBG("Opened a packet in \"open channel packets\" command: stream id = %" PRIu64
				    ", channel name = %s, session id = %" PRIu64,
				    stream->key,
				    stream->chan->name,
				    stream->chan->session_id);
				stream->opened_packet_in_current_trace_chunk = true;
				break;
			case CONSUMER_STREAM_OPEN_PACKET_STATUS_NO_SPACE:
				DBG("No space left to open a packet in \"open channel packets\" command: stream id = %" PRIu64
				    ", channel name = %s, session id = %" PRIu64,
				    stream->key,
				    stream->chan->name,
				    stream->chan->session_id);
				break;
			case CONSUMER_STREAM_OPEN_PACKET_STATUS_ERROR:
				/*
				 * Only unexpected internal errors can lead to this
				 * failing. Report an unknown error.
				 */
				ERR("Failed to flush empty buffer in \"open channel packets\" command: stream id = %" PRIu64
				    ", channel id = %" PRIu64 ", channel name = %s"
				    ", session id = %" PRIu64,
				    stream->key,
				    channel->key,
				    channel->name,
				    channel->session_id);
				ret = LTTCOMM_CONSUMERD_UNKNOWN_ERROR;
				goto error_unlock;
			default:
				abort();
			}

		next:
			pthread_mutex_unlock(&stream->lock);
		}
	}
end_rcu_unlock:
end:
	return ret;

error_unlock:
	pthread_mutex_unlock(&stream->lock);
	goto end_rcu_unlock;
}

void lttng_consumer_sigbus_handle(void *addr)
{
	lttng_ustconsumer_sigbus_handle(addr);
}
