/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
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
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>

#include <bin/lttng-consumerd/health-consumerd.h>
#include <common/common.h>
#include <common/utils.h>
#include <common/compat/poll.h>
#include <common/compat/endian.h>
#include <common/index/index.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/relayd.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/relayd/relayd.h>
#include <common/ust-consumer/ust-consumer.h>
#include <common/consumer/consumer-timer.h>
#include <common/consumer/consumer.h>
#include <common/consumer/consumer-stream.h>
#include <common/consumer/consumer-testpoint.h>
#include <common/align.h>
#include <common/consumer/consumer-metadata-cache.h>

struct lttng_consumer_global_data consumer_data = {
	.stream_count = 0,
	.need_update = 1,
	.type = LTTNG_CONSUMER_UNKNOWN,
};

enum consumer_channel_action {
	CONSUMER_CHANNEL_ADD,
	CONSUMER_CHANNEL_DEL,
	CONSUMER_CHANNEL_QUIT,
};

struct consumer_channel_msg {
	enum consumer_channel_action action;
	struct lttng_consumer_channel *chan;	/* add */
	uint64_t key;				/* del */
};

/* Flag used to temporarily pause data consumption from testpoints. */
int data_consumption_paused;

/*
 * Flag to inform the polling thread to quit when all fd hung up. Updated by
 * the consumer_thread_receive_fds when it notices that all fds has hung up.
 * Also updated by the signal handler (consumer_should_exit()). Read by the
 * polling threads.
 */
int consumer_quit;

/*
 * Global hash table containing respectively metadata and data streams. The
 * stream element in this ht should only be updated by the metadata poll thread
 * for the metadata and the data poll thread for the data.
 */
static struct lttng_ht *metadata_ht;
static struct lttng_ht *data_ht;

/*
 * Notify a thread lttng pipe to poll back again. This usually means that some
 * global state has changed so we just send back the thread in a poll wait
 * call.
 */
static void notify_thread_lttng_pipe(struct lttng_pipe *pipe)
{
	struct lttng_consumer_stream *null_stream = NULL;

	assert(pipe);

	(void) lttng_pipe_write(pipe, &null_stream, sizeof(null_stream));
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

void notify_thread_del_channel(struct lttng_consumer_local_data *ctx,
		uint64_t key)
{
	notify_channel_pipe(ctx, NULL, key, CONSUMER_CHANNEL_DEL);
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

	assert(channel);

	/* Delete streams that might have been left in the stream list. */
	cds_list_for_each_entry_safe(stream, stmp, &channel->streams.head,
			send_node) {
		cds_list_del(&stream->send_node);
		/*
		 * Once a stream is added to this list, the buffers were created so we
		 * have a guarantee that this call will succeed. Setting the monitor
		 * mode to 0 so we don't lock nor try to delete the stream from the
		 * global hash table.
		 */
		stream->monitor = 0;
		consumer_stream_destroy(stream, NULL);
	}
}

/*
 * Find a stream. The consumer_data.lock must be locked during this
 * call.
 */
static struct lttng_consumer_stream *find_stream(uint64_t key,
		struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct lttng_consumer_stream *stream = NULL;

	assert(ht);

	/* -1ULL keys are lookup failures */
	if (key == (uint64_t) -1ULL) {
		return NULL;
	}

	rcu_read_lock();

	lttng_ht_lookup(ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != NULL) {
		stream = caa_container_of(node, struct lttng_consumer_stream, node);
	}

	rcu_read_unlock();

	return stream;
}

static void steal_stream_key(uint64_t key, struct lttng_ht *ht)
{
	struct lttng_consumer_stream *stream;

	rcu_read_lock();
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
	rcu_read_unlock();
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
	struct lttng_consumer_channel *channel = NULL;

	/* -1ULL keys are lookup failures */
	if (key == (uint64_t) -1ULL) {
		return NULL;
	}

	lttng_ht_lookup(consumer_data.channel_ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != NULL) {
		channel = caa_container_of(node, struct lttng_consumer_channel, node);
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

	rcu_read_lock();
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
	rcu_read_unlock();
}

static void free_channel_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node =
		caa_container_of(head, struct lttng_ht_node_u64, head);
	struct lttng_consumer_channel *channel =
		caa_container_of(node, struct lttng_consumer_channel, node);

	switch (consumer_data.type) {
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
	free(channel);
}

/*
 * RCU protected relayd socket pair free.
 */
static void free_relayd_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node =
		caa_container_of(head, struct lttng_ht_node_u64, head);
	struct consumer_relayd_sock_pair *relayd =
		caa_container_of(node, struct consumer_relayd_sock_pair, node);

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

	free(relayd);
}

/*
 * Destroy and free relayd socket pair object.
 */
void consumer_destroy_relayd(struct consumer_relayd_sock_pair *relayd)
{
	int ret;
	struct lttng_ht_iter iter;

	if (relayd == NULL) {
		return;
	}

	DBG("Consumer destroy and close relayd socket pair");

	iter.iter.node = &relayd->node.node;
	ret = lttng_ht_del(consumer_data.relayd_ht, &iter);
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
	int ret;
	struct lttng_ht_iter iter;

	DBG("Consumer delete channel key %" PRIu64, channel->key);

	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&channel->lock);

	/* Destroy streams that might have been left in the stream list. */
	clean_channel_stream_list(channel);

	if (channel->live_timer_enabled == 1) {
		consumer_timer_live_stop(channel);
	}
	if (channel->monitor_timer_enabled == 1) {
		consumer_timer_monitor_stop(channel);
	}

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		lttng_ustconsumer_del_channel(channel);
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		goto end;
	}

	rcu_read_lock();
	iter.iter.node = &channel->node.node;
	ret = lttng_ht_del(consumer_data.channel_ht, &iter);
	assert(!ret);
	rcu_read_unlock();

	call_rcu(&channel->node.head, free_channel_rcu);
end:
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&consumer_data.lock);
}

/*
 * Iterate over the relayd hash table and destroy each element. Finally,
 * destroy the whole hash table.
 */
static void cleanup_relayd_ht(void)
{
	struct lttng_ht_iter iter;
	struct consumer_relayd_sock_pair *relayd;

	rcu_read_lock();

	cds_lfht_for_each_entry(consumer_data.relayd_ht->ht, &iter.iter, relayd,
			node.node) {
		consumer_destroy_relayd(relayd);
	}

	rcu_read_unlock();

	lttng_ht_destroy(consumer_data.relayd_ht);
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

	rcu_read_lock();

	/* Let's begin with metadata */
	cds_lfht_for_each_entry(metadata_ht->ht, &iter.iter, stream, node.node) {
		if (stream->net_seq_idx == net_seq_idx) {
			uatomic_set(&stream->endpoint_status, status);
			DBG("Delete flag set to metadata stream %d", stream->wait_fd);
		}
	}

	/* Follow up by the data streams */
	cds_lfht_for_each_entry(data_ht->ht, &iter.iter, stream, node.node) {
		if (stream->net_seq_idx == net_seq_idx) {
			uatomic_set(&stream->endpoint_status, status);
			DBG("Delete flag set to data stream %d", stream->wait_fd);
		}
	}
	rcu_read_unlock();
}

/*
 * Cleanup a relayd object by flagging every associated streams for deletion,
 * destroying the object meaning removing it from the relayd hash table,
 * closing the sockets and freeing the memory in a RCU call.
 *
 * If a local data context is available, notify the threads that the streams'
 * state have changed.
 */
static void cleanup_relayd(struct consumer_relayd_sock_pair *relayd,
		struct lttng_consumer_local_data *ctx)
{
	uint64_t netidx;

	assert(relayd);

	DBG("Cleaning up relayd sockets");

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
	if (ctx) {
		notify_thread_lttng_pipe(ctx->consumer_data_pipe);
		notify_thread_lttng_pipe(ctx->consumer_metadata_pipe);
	}
}

/*
 * Flag a relayd socket pair for destruction. Destroy it if the refcount
 * reaches zero.
 *
 * RCU read side lock MUST be aquired before calling this function.
 */
void consumer_flag_relayd_for_destroy(struct consumer_relayd_sock_pair *relayd)
{
	assert(relayd);

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
void consumer_del_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
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

struct lttng_consumer_stream *consumer_allocate_stream(uint64_t channel_key,
		uint64_t stream_key,
		enum lttng_consumer_stream_state state,
		const char *channel_name,
		uid_t uid,
		gid_t gid,
		uint64_t relayd_id,
		uint64_t session_id,
		int cpu,
		int *alloc_ret,
		enum consumer_channel_type type,
		unsigned int monitor)
{
	int ret;
	struct lttng_consumer_stream *stream;

	stream = zmalloc(sizeof(*stream));
	if (stream == NULL) {
		PERROR("malloc struct lttng_consumer_stream");
		ret = -ENOMEM;
		goto end;
	}

	rcu_read_lock();

	stream->key = stream_key;
	stream->out_fd = -1;
	stream->out_fd_offset = 0;
	stream->output_written = 0;
	stream->state = state;
	stream->uid = uid;
	stream->gid = gid;
	stream->net_seq_idx = relayd_id;
	stream->session_id = session_id;
	stream->monitor = monitor;
	stream->endpoint_status = CONSUMER_ENDPOINT_ACTIVE;
	stream->index_file = NULL;
	stream->last_sequence_number = -1ULL;
	pthread_mutex_init(&stream->lock, NULL);
	pthread_mutex_init(&stream->metadata_timer_lock, NULL);

	/* If channel is the metadata, flag this stream as metadata. */
	if (type == CONSUMER_CHANNEL_TYPE_METADATA) {
		stream->metadata_flag = 1;
		/* Metadata is flat out. */
		strncpy(stream->name, DEFAULT_METADATA_NAME, sizeof(stream->name));
		/* Live rendez-vous point. */
		pthread_cond_init(&stream->metadata_rdv, NULL);
		pthread_mutex_init(&stream->metadata_rdv_lock, NULL);
	} else {
		/* Format stream name to <channel_name>_<cpu_number> */
		ret = snprintf(stream->name, sizeof(stream->name), "%s_%d",
				channel_name, cpu);
		if (ret < 0) {
			PERROR("snprintf stream name");
			goto error;
		}
	}

	/* Key is always the wait_fd for streams. */
	lttng_ht_node_init_u64(&stream->node, stream->key);

	/* Init node per channel id key */
	lttng_ht_node_init_u64(&stream->node_channel_id, channel_key);

	/* Init session id node with the stream session id */
	lttng_ht_node_init_u64(&stream->node_session_id, stream->session_id);

	DBG3("Allocated stream %s (key %" PRIu64 ", chan_key %" PRIu64
			" relayd_id %" PRIu64 ", session_id %" PRIu64,
			stream->name, stream->key, channel_key,
			stream->net_seq_idx, stream->session_id);

	rcu_read_unlock();
	return stream;

error:
	rcu_read_unlock();
	free(stream);
end:
	if (alloc_ret) {
		*alloc_ret = ret;
	}
	return NULL;
}

/*
 * Add a stream to the global list protected by a mutex.
 */
void consumer_add_data_stream(struct lttng_consumer_stream *stream)
{
	struct lttng_ht *ht = data_ht;

	assert(stream);
	assert(ht);

	DBG3("Adding consumer stream %" PRIu64, stream->key);

	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&stream->chan->lock);
	pthread_mutex_lock(&stream->chan->timer_lock);
	pthread_mutex_lock(&stream->lock);
	rcu_read_lock();

	/* Steal stream identifier to avoid having streams with the same key */
	steal_stream_key(stream->key, ht);

	lttng_ht_add_unique_u64(ht, &stream->node);

	lttng_ht_add_u64(consumer_data.stream_per_chan_id_ht,
			&stream->node_channel_id);

	/*
	 * Add stream to the stream_list_ht of the consumer data. No need to steal
	 * the key since the HT does not use it and we allow to add redundant keys
	 * into this table.
	 */
	lttng_ht_add_u64(consumer_data.stream_list_ht, &stream->node_session_id);

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
	consumer_data.stream_count++;
	consumer_data.need_update = 1;

	rcu_read_unlock();
	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&stream->chan->timer_lock);
	pthread_mutex_unlock(&stream->chan->lock);
	pthread_mutex_unlock(&consumer_data.lock);
}

void consumer_del_data_stream(struct lttng_consumer_stream *stream)
{
	consumer_del_stream(stream, data_ht);
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

	assert(relayd);

	lttng_ht_lookup(consumer_data.relayd_ht,
			&relayd->net_seq_idx, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != NULL) {
		goto end;
	}
	lttng_ht_add_unique_u64(consumer_data.relayd_ht, &relayd->node);

end:
	return ret;
}

/*
 * Allocate and return a consumer relayd socket.
 */
static struct consumer_relayd_sock_pair *consumer_allocate_relayd_sock_pair(
		uint64_t net_seq_idx)
{
	struct consumer_relayd_sock_pair *obj = NULL;

	/* net sequence index of -1 is a failure */
	if (net_seq_idx == (uint64_t) -1ULL) {
		goto error;
	}

	obj = zmalloc(sizeof(struct consumer_relayd_sock_pair));
	if (obj == NULL) {
		PERROR("zmalloc relayd sock");
		goto error;
	}

	obj->net_seq_idx = net_seq_idx;
	obj->refcount = 0;
	obj->destroy_flag = 0;
	obj->control_sock.sock.fd = -1;
	obj->data_sock.sock.fd = -1;
	lttng_ht_node_init_u64(&obj->node, obj->net_seq_idx);
	pthread_mutex_init(&obj->ctrl_sock_mutex, NULL);

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
	struct consumer_relayd_sock_pair *relayd = NULL;

	/* Negative keys are lookup failures */
	if (key == (uint64_t) -1ULL) {
		goto error;
	}

	lttng_ht_lookup(consumer_data.relayd_ht, &key,
			&iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node != NULL) {
		relayd = caa_container_of(node, struct consumer_relayd_sock_pair, node);
	}

error:
	return relayd;
}

/*
 * Find a relayd and send the stream
 *
 * Returns 0 on success, < 0 on error
 */
int consumer_send_relayd_stream(struct lttng_consumer_stream *stream,
		char *path)
{
	int ret = 0;
	struct consumer_relayd_sock_pair *relayd;

	assert(stream);
	assert(stream->net_seq_idx != -1ULL);
	assert(path);

	/* The stream is not metadata. Get relayd reference if exists. */
	rcu_read_lock();
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd != NULL) {
		/* Add stream on the relayd */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_add_stream(&relayd->control_sock, stream->name,
				path, &stream->relayd_stream_id,
				stream->chan->tracefile_size, stream->chan->tracefile_count);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
			goto end;
		}

		uatomic_inc(&relayd->refcount);
		stream->sent_to_relayd = 1;
	} else {
		ERR("Stream %" PRIu64 " relayd ID %" PRIu64 " unknown. Can't send it.",
				stream->key, stream->net_seq_idx);
		ret = -1;
		goto end;
	}

	DBG("Stream %s with key %" PRIu64 " sent to relayd id %" PRIu64,
			stream->name, stream->key, stream->net_seq_idx);

end:
	rcu_read_unlock();
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

	assert(net_seq_idx != -1ULL);

	/* The stream is not metadata. Get relayd reference if exists. */
	rcu_read_lock();
	relayd = consumer_find_relayd(net_seq_idx);
	if (relayd != NULL) {
		/* Add stream on the relayd */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_streams_sent(&relayd->control_sock);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
			goto end;
		}
	} else {
		ERR("Relayd ID %" PRIu64 " unknown. Can't send streams_sent.",
				net_seq_idx);
		ret = -1;
		goto end;
	}

	ret = 0;
	DBG("All streams sent relayd id %" PRIu64, net_seq_idx);

end:
	rcu_read_unlock();
	return ret;
}

/*
 * Find a relayd and close the stream
 */
void close_relayd_stream(struct lttng_consumer_stream *stream)
{
	struct consumer_relayd_sock_pair *relayd;

	/* The stream is not metadata. Get relayd reference if exists. */
	rcu_read_lock();
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd) {
		consumer_stream_relayd_close(stream, relayd);
	}
	rcu_read_unlock();
}

/*
 * Handle stream for relayd transmission if the stream applies for network
 * streaming where the net sequence index is set.
 *
 * Return destination file descriptor or negative value on error.
 */
static int write_relayd_stream_header(struct lttng_consumer_stream *stream,
		size_t data_size, unsigned long padding,
		struct consumer_relayd_sock_pair *relayd)
{
	int outfd = -1, ret;
	struct lttcomm_relayd_data_hdr data_hdr;

	/* Safety net */
	assert(stream);
	assert(relayd);

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

		ret = relayd_send_data_hdr(&relayd->data_sock, &data_hdr,
				sizeof(data_hdr));
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
 * Allocate and return a new lttng_consumer_channel object using the given key
 * to initialize the hash table node.
 *
 * On error, return NULL.
 */
struct lttng_consumer_channel *consumer_allocate_channel(uint64_t key,
		uint64_t session_id,
		const char *pathname,
		const char *name,
		uid_t uid,
		gid_t gid,
		uint64_t relayd_id,
		enum lttng_event_output output,
		uint64_t tracefile_size,
		uint64_t tracefile_count,
		uint64_t session_id_per_pid,
		unsigned int monitor,
		unsigned int live_timer_interval,
		const char *root_shm_path,
		const char *shm_path)
{
	struct lttng_consumer_channel *channel;

	channel = zmalloc(sizeof(*channel));
	if (channel == NULL) {
		PERROR("malloc struct lttng_consumer_channel");
		goto end;
	}

	channel->key = key;
	channel->refcount = 0;
	channel->session_id = session_id;
	channel->session_id_per_pid = session_id_per_pid;
	channel->uid = uid;
	channel->gid = gid;
	channel->relayd_id = relayd_id;
	channel->tracefile_size = tracefile_size;
	channel->tracefile_count = tracefile_count;
	channel->monitor = monitor;
	channel->live_timer_interval = live_timer_interval;
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
		assert(0);
		free(channel);
		channel = NULL;
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

	channel->wait_fd = -1;

	CDS_INIT_LIST_HEAD(&channel->streams.head);

	DBG("Allocated channel (key %" PRIu64 ")", channel->key);

end:
	return channel;
}

/*
 * Add a channel to the global list protected by a mutex.
 *
 * Always return 0 indicating success.
 */
int consumer_add_channel(struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx)
{
	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&channel->lock);
	pthread_mutex_lock(&channel->timer_lock);

	/*
	 * This gives us a guarantee that the channel we are about to add to the
	 * channel hash table will be unique. See this function comment on the why
	 * we need to steel the channel key at this stage.
	 */
	steal_channel_key(channel->key);

	rcu_read_lock();
	lttng_ht_add_unique_u64(consumer_data.channel_ht, &channel->node);
	rcu_read_unlock();

	pthread_mutex_unlock(&channel->timer_lock);
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&consumer_data.lock);

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
		struct pollfd **pollfd, struct lttng_consumer_stream **local_stream,
		struct lttng_ht *ht)
{
	int i = 0;
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	assert(ctx);
	assert(ht);
	assert(pollfd);
	assert(local_stream);

	DBG("Updating poll fd array");
	rcu_read_lock();
	cds_lfht_for_each_entry(ht->ht, &iter.iter, stream, node.node) {
		/*
		 * Only active streams with an active end point can be added to the
		 * poll set and local stream storage of the thread.
		 *
		 * There is a potential race here for endpoint_status to be updated
		 * just after the check. However, this is OK since the stream(s) will
		 * be deleted once the thread is notified that the end point state has
		 * changed where this function will be called back again.
		 */
		if (stream->state != LTTNG_CONSUMER_ACTIVE_STREAM ||
				stream->endpoint_status == CONSUMER_ENDPOINT_INACTIVE) {
			continue;
		}
		/*
		 * This clobbers way too much the debug output. Uncomment that if you
		 * need it for debugging purposes.
		 *
		 * DBG("Active FD %d", stream->wait_fd);
		 */
		(*pollfd)[i].fd = stream->wait_fd;
		(*pollfd)[i].events = POLLIN | POLLPRI;
		local_stream[i] = stream;
		i++;
	}
	rcu_read_unlock();

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
void lttng_consumer_set_error_sock(struct lttng_consumer_local_data *ctx,
		int sock)
{
	ctx->consumer_error_socket = sock;
}

/*
 * Set the command socket path.
 */
void lttng_consumer_set_command_sock_path(
		struct lttng_consumer_local_data *ctx, char *sock)
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
		return lttcomm_send_unix_sock(ctx->consumer_error_socket, &cmd,
				sizeof(enum lttcomm_sessiond_command));
	}

	return 0;
}

/*
 * Close all the tracefiles and stream fds and MUST be called when all
 * instances are destroyed i.e. when all threads were joined and are ended.
 */
void lttng_consumer_cleanup(void)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *channel;

	rcu_read_lock();

	cds_lfht_for_each_entry(consumer_data.channel_ht->ht, &iter.iter, channel,
			node.node) {
		consumer_del_channel(channel);
	}

	rcu_read_unlock();

	lttng_ht_destroy(consumer_data.channel_ht);

	cleanup_relayd_ht();

	lttng_ht_destroy(consumer_data.stream_per_chan_id_ht);

	/*
	 * This HT contains streams that are freed by either the metadata thread or
	 * the data thread so we do *nothing* on the hash table and simply destroy
	 * it.
	 */
	lttng_ht_destroy(consumer_data.stream_list_ht);
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
static
void lttng_consumer_sync_trace_file(struct lttng_consumer_stream *stream,
		off_t orig_offset)
{
	int ret;
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
	lttng_sync_file_range(outfd, orig_offset - stream->max_sb_size,
			stream->max_sb_size,
			SYNC_FILE_RANGE_WAIT_BEFORE
			| SYNC_FILE_RANGE_WRITE
			| SYNC_FILE_RANGE_WAIT_AFTER);
	/*
	 * Give hints to the kernel about how we access the file:
	 * POSIX_FADV_DONTNEED : we won't re-access data in a near future after
	 * we write it.
	 *
	 * We need to call fadvise again after the file grows because the
	 * kernel does not seem to apply fadvise to non-existing parts of the
	 * file.
	 *
	 * Call fadvise _after_ having waited for the page writeback to
	 * complete because the dirty page writeback semantic is not well
	 * defined. So it can be expected to lead to lower throughput in
	 * streaming.
	 */
	ret = posix_fadvise(outfd, orig_offset - stream->max_sb_size,
			stream->max_sb_size, POSIX_FADV_DONTNEED);
	if (ret && ret != -ENOSYS) {
		errno = ret;
		PERROR("posix_fadvise on fd %i", outfd);
	}
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
struct lttng_consumer_local_data *lttng_consumer_create(
		enum lttng_consumer_type type,
		ssize_t (*buffer_ready)(struct lttng_consumer_stream *stream,
			struct lttng_consumer_local_data *ctx),
		int (*recv_channel)(struct lttng_consumer_channel *channel),
		int (*recv_stream)(struct lttng_consumer_stream *stream),
		int (*update_stream)(uint64_t stream_key, uint32_t state))
{
	int ret;
	struct lttng_consumer_local_data *ctx;

	assert(consumer_data.type == LTTNG_CONSUMER_UNKNOWN ||
		consumer_data.type == type);
	consumer_data.type = type;

	ctx = zmalloc(sizeof(struct lttng_consumer_local_data));
	if (ctx == NULL) {
		PERROR("allocating context");
		goto error;
	}

	ctx->consumer_error_socket = -1;
	ctx->consumer_metadata_socket = -1;
	pthread_mutex_init(&ctx->metadata_socket_lock, NULL);
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
	return NULL;
}

/*
 * Iterate over all streams of the hashtable and free them properly.
 */
static void destroy_data_stream_ht(struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	if (ht == NULL) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(ht->ht, &iter.iter, stream, node.node) {
		/*
		 * Ignore return value since we are currently cleaning up so any error
		 * can't be handled.
		 */
		(void) consumer_del_stream(stream, ht);
	}
	rcu_read_unlock();

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

	if (ht == NULL) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(ht->ht, &iter.iter, stream, node.node) {
		/*
		 * Ignore return value since we are currently cleaning up so any error
		 * can't be handled.
		 */
		(void) consumer_del_metadata_stream(stream, ht);
	}
	rcu_read_unlock();

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
static int write_relayd_metadata_id(int fd,
		struct lttng_consumer_stream *stream,
		struct consumer_relayd_sock_pair *relayd, unsigned long padding)
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
			stream->relayd_stream_id, padding);

end:
	return (int) ret;
}

/*
 * Mmap the ring buffer, read it and write the data to the tracefile. This is a
 * core function for writing trace buffers to either the local filesystem or
 * the network.
 *
 * It must be called with the stream lock held.
 *
 * Careful review MUST be put if any changes occur!
 *
 * Returns the number of bytes written
 */
ssize_t lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding,
		struct ctf_packet_index *index)
{
	unsigned long mmap_offset;
	void *mmap_base;
	ssize_t ret = 0;
	off_t orig_offset = stream->out_fd_offset;
	/* Default is on the disk */
	int outfd = stream->out_fd;
	struct consumer_relayd_sock_pair *relayd = NULL;
	unsigned int relayd_hang_up = 0;

	/* RCU lock for the relayd pointer */
	rcu_read_lock();

	/* Flag that the current stream if set for network streaming. */
	if (stream->net_seq_idx != (uint64_t) -1ULL) {
		relayd = consumer_find_relayd(stream->net_seq_idx);
		if (relayd == NULL) {
			ret = -EPIPE;
			goto end;
		}
	}

	/* get the offset inside the fd to mmap */
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		mmap_base = stream->mmap_base;
		ret = kernctl_get_mmap_read_offset(stream->wait_fd, &mmap_offset);
		if (ret < 0) {
			PERROR("tracer ctl get_mmap_read_offset");
			goto end;
		}
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		mmap_base = lttng_ustctl_get_mmap_base(stream);
		if (!mmap_base) {
			ERR("read mmap get mmap base for stream %s", stream->name);
			ret = -EPERM;
			goto end;
		}
		ret = lttng_ustctl_get_mmap_read_offset(stream, &mmap_offset);
		if (ret != 0) {
			PERROR("tracer ctl get_mmap_read_offset");
			ret = -EINVAL;
			goto end;
		}
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
	}

	/* Handle stream on the relayd if the output is on the network */
	if (relayd) {
		unsigned long netlen = len;

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
			ret = write_relayd_metadata_id(outfd, stream, relayd, padding);
			if (ret < 0) {
				relayd_hang_up = 1;
				goto write_error;
			}
		}
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
				(stream->tracefile_size_current + len) >
				stream->chan->tracefile_size) {
			ret = utils_rotate_stream_file(stream->chan->pathname,
					stream->name, stream->chan->tracefile_size,
					stream->chan->tracefile_count, stream->uid, stream->gid,
					stream->out_fd, &(stream->tracefile_count_current),
					&stream->out_fd);
			if (ret < 0) {
				ERR("Rotating output file");
				goto end;
			}
			outfd = stream->out_fd;

			if (stream->index_file) {
				lttng_index_file_put(stream->index_file);
				stream->index_file = lttng_index_file_create(stream->chan->pathname,
						stream->name, stream->uid, stream->gid,
						stream->chan->tracefile_size,
						stream->tracefile_count_current,
						CTF_INDEX_MAJOR, CTF_INDEX_MINOR);
				if (!stream->index_file) {
					goto end;
				}
			}

			/* Reset current size because we just perform a rotation. */
			stream->tracefile_size_current = 0;
			stream->out_fd_offset = 0;
			orig_offset = 0;
		}
		stream->tracefile_size_current += len;
		if (index) {
			index->offset = htobe64(stream->out_fd_offset);
		}
	}

	/*
	 * This call guarantee that len or less is returned. It's impossible to
	 * receive a ret value that is bigger than len.
	 */
	ret = lttng_write(outfd, mmap_base + mmap_offset, len);
	DBG("Consumer mmap write() ret %zd (len %lu)", ret, len);
	if (ret < 0 || ((size_t) ret != len)) {
		/*
		 * Report error to caller if nothing was written else at least send the
		 * amount written.
		 */
		if (ret < 0) {
			ret = -errno;
		}
		relayd_hang_up = 1;

		/* Socket operation failed. We consider the relayd dead */
		if (errno == EPIPE || errno == EINVAL || errno == EBADF) {
			/*
			 * This is possible if the fd is closed on the other side
			 * (outfd) or any write problem. It can be verbose a bit for a
			 * normal execution if for instance the relayd is stopped
			 * abruptly. This can happen so set this to a DBG statement.
			 */
			DBG("Consumer mmap write detected relayd hang up");
		} else {
			/* Unhandled error, print it and stop function right now. */
			PERROR("Error in write mmap (ret %zd != len %lu)", ret, len);
		}
		goto write_error;
	}
	stream->output_written += ret;

	/* This call is useless on a socket so better save a syscall. */
	if (!relayd) {
		/* This won't block, but will start writeout asynchronously */
		lttng_sync_file_range(outfd, stream->out_fd_offset, len,
				SYNC_FILE_RANGE_WRITE);
		stream->out_fd_offset += len;
		lttng_consumer_sync_trace_file(stream, orig_offset);
	}

write_error:
	/*
	 * This is a special case that the relayd has closed its socket. Let's
	 * cleanup the relayd object and all associated streams.
	 */
	if (relayd && relayd_hang_up) {
		cleanup_relayd(relayd, ctx);
	}

end:
	/* Unlock only if ctrl socket used */
	if (relayd && stream->metadata_flag) {
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	}

	rcu_read_unlock();
	return ret;
}

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * It must be called with the stream lock held.
 *
 * Returns the number of bytes spliced.
 */
ssize_t lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding,
		struct ctf_packet_index *index)
{
	ssize_t ret = 0, written = 0, ret_splice = 0;
	loff_t offset = 0;
	off_t orig_offset = stream->out_fd_offset;
	int fd = stream->wait_fd;
	/* Default is on the disk */
	int outfd = stream->out_fd;
	struct consumer_relayd_sock_pair *relayd = NULL;
	int *splice_pipe;
	unsigned int relayd_hang_up = 0;

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		/* Not supported for user space tracing */
		return -ENOSYS;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
	}

	/* RCU lock for the relayd pointer */
	rcu_read_lock();

	/* Flag that the current stream if set for network streaming. */
	if (stream->net_seq_idx != (uint64_t) -1ULL) {
		relayd = consumer_find_relayd(stream->net_seq_idx);
		if (relayd == NULL) {
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
			ret = write_relayd_metadata_id(splice_pipe[1], stream, relayd,
					padding);
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
				(stream->tracefile_size_current + len) >
				stream->chan->tracefile_size) {
			ret = utils_rotate_stream_file(stream->chan->pathname,
					stream->name, stream->chan->tracefile_size,
					stream->chan->tracefile_count, stream->uid, stream->gid,
					stream->out_fd, &(stream->tracefile_count_current),
					&stream->out_fd);
			if (ret < 0) {
				written = ret;
				ERR("Rotating output file");
				goto end;
			}
			outfd = stream->out_fd;

			if (stream->index_file) {
				lttng_index_file_put(stream->index_file);
				stream->index_file = lttng_index_file_create(stream->chan->pathname,
						stream->name, stream->uid, stream->gid,
						stream->chan->tracefile_size,
						stream->tracefile_count_current,
						CTF_INDEX_MAJOR, CTF_INDEX_MINOR);
				if (!stream->index_file) {
					goto end;
				}
			}

			/* Reset current size because we just perform a rotation. */
			stream->tracefile_size_current = 0;
			stream->out_fd_offset = 0;
			orig_offset = 0;
		}
		stream->tracefile_size_current += len;
		index->offset = htobe64(stream->out_fd_offset);
	}

	while (len > 0) {
		DBG("splice chan to pipe offset %lu of len %lu (fd : %d, pipe: %d)",
				(unsigned long)offset, len, fd, splice_pipe[1]);
		ret_splice = splice(fd, &offset, splice_pipe[1], NULL, len,
				SPLICE_F_MOVE | SPLICE_F_MORE);
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
		ret_splice = splice(splice_pipe[0], NULL, outfd, NULL,
				ret_splice, SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("Consumer splice pipe to file (out_fd: %d), ret %zd",
				outfd, ret_splice);
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
			PERROR("Wrote more data than requested %zd (len: %lu)", ret_splice,
					len);
			goto splice_error;
		} else {
			/* All good, update current len and continue. */
			len -= ret_splice;
		}

		/* This call is useless on a socket so better save a syscall. */
		if (!relayd) {
			/* This won't block, but will start writeout asynchronously */
			lttng_sync_file_range(outfd, stream->out_fd_offset, ret_splice,
					SYNC_FILE_RANGE_WRITE);
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
		cleanup_relayd(relayd, ctx);
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

	rcu_read_unlock();
	return written;
}

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_take_snapshot(struct lttng_consumer_stream *stream)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_take_snapshot(stream);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_take_snapshot(stream);
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		return -ENOSYS;
	}
}

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_consumer_get_produced_snapshot(struct lttng_consumer_stream *stream,
		unsigned long *pos)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_get_produced_snapshot(stream, pos);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_get_produced_snapshot(stream, pos);
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		return -ENOSYS;
	}
}

int lttng_consumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_recv_cmd(ctx, sock, consumer_sockpoll);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_recv_cmd(ctx, sock, consumer_sockpoll);
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		return -ENOSYS;
	}
}

void lttng_consumer_close_all_metadata(void)
{
	switch (consumer_data.type) {
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
		assert(0);
	}
}

/*
 * Clean up a metadata stream and free its memory.
 */
void consumer_del_metadata_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
{
	struct lttng_consumer_channel *free_chan = NULL;

	assert(stream);
	/*
	 * This call should NEVER receive regular stream. It must always be
	 * metadata stream and this is crucial for data structure synchronization.
	 */
	assert(stream->metadata_flag);

	DBG3("Consumer delete metadata stream %d", stream->wait_fd);

	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&stream->chan->lock);
	pthread_mutex_lock(&stream->lock);
	if (stream->chan->metadata_cache) {
		/* Only applicable to userspace consumers. */
		pthread_mutex_lock(&stream->chan->metadata_cache->lock);
	}

	/* Remove any reference to that stream. */
	consumer_stream_delete(stream, ht);

	/* Close down everything including the relayd if one. */
	consumer_stream_close(stream);
	/* Destroy tracer buffers of the stream. */
	consumer_stream_destroy_buffers(stream);

	/* Atomically decrement channel refcount since other threads can use it. */
	if (!uatomic_sub_return(&stream->chan->refcount, 1)
			&& !uatomic_read(&stream->chan->nb_init_stream_left)) {
		/* Go for channel deletion! */
		free_chan = stream->chan;
	}

	/*
	 * Nullify the stream reference so it is not used after deletion. The
	 * channel lock MUST be acquired before being able to check for a NULL
	 * pointer value.
	 */
	stream->chan->metadata_stream = NULL;

	if (stream->chan->metadata_cache) {
		pthread_mutex_unlock(&stream->chan->metadata_cache->lock);
	}
	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&stream->chan->lock);
	pthread_mutex_unlock(&consumer_data.lock);

	if (free_chan) {
		consumer_del_channel(free_chan);
	}

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

	assert(stream);
	assert(ht);

	DBG3("Adding metadata stream %" PRIu64 " to hash table", stream->key);

	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&stream->chan->lock);
	pthread_mutex_lock(&stream->chan->timer_lock);
	pthread_mutex_lock(&stream->lock);

	/*
	 * From here, refcounts are updated so be _careful_ when returning an error
	 * after this point.
	 */

	rcu_read_lock();

	/*
	 * Lookup the stream just to make sure it does not exist in our internal
	 * state. This should NEVER happen.
	 */
	lttng_ht_lookup(ht, &stream->key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	assert(!node);

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

	lttng_ht_add_unique_u64(consumer_data.stream_per_chan_id_ht,
		&stream->node_channel_id);

	/*
	 * Add stream to the stream_list_ht of the consumer data. No need to steal
	 * the key since the HT does not use it and we allow to add redundant keys
	 * into this table.
	 */
	lttng_ht_add_u64(consumer_data.stream_list_ht, &stream->node_session_id);

	rcu_read_unlock();

	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&stream->chan->lock);
	pthread_mutex_unlock(&stream->chan->timer_lock);
	pthread_mutex_unlock(&consumer_data.lock);
}

/*
 * Delete data stream that are flagged for deletion (endpoint_status).
 */
static void validate_endpoint_status_data_stream(void)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	DBG("Consumer delete flagged data stream");

	rcu_read_lock();
	cds_lfht_for_each_entry(data_ht->ht, &iter.iter, stream, node.node) {
		/* Validate delete flag of the stream */
		if (stream->endpoint_status == CONSUMER_ENDPOINT_ACTIVE) {
			continue;
		}
		/* Delete it right now */
		consumer_del_stream(stream, data_ht);
	}
	rcu_read_unlock();
}

/*
 * Delete metadata stream that are flagged for deletion (endpoint_status).
 */
static void validate_endpoint_status_metadata_stream(
		struct lttng_poll_event *pollset)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	DBG("Consumer delete flagged metadata stream");

	assert(pollset);

	rcu_read_lock();
	cds_lfht_for_each_entry(metadata_ht->ht, &iter.iter, stream, node.node) {
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
	rcu_read_unlock();
}

/*
 * Thread polls on metadata file descriptor and write them on disk or on the
 * network.
 */
void *consumer_thread_metadata_poll(void *data)
{
	int ret, i, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_consumer_stream *stream = NULL;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct lttng_poll_event events;
	struct lttng_consumer_local_data *ctx = data;
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

	ret = lttng_poll_add(&events,
			lttng_pipe_get_readfd(ctx->consumer_metadata_pipe), LPOLLIN);
	if (ret < 0) {
		goto end;
	}

	/* Main loop */
	DBG("Metadata main loop started");

	while (1) {
restart:
		health_code_update();
		health_poll_entry();
		DBG("Metadata poll wait");
		ret = lttng_poll_wait(&events, -1);
		DBG("Metadata poll return from wait with %d fd(s)",
				LTTNG_POLL_GETNB(&events));
		health_poll_exit();
		DBG("Metadata event caught in thread");
		if (ret < 0) {
			if (errno == EINTR) {
				ERR("Poll EINTR caught");
				goto restart;
			}
			if (LTTNG_POLL_GETNB(&events) == 0) {
				err = 0;	/* All is OK */
			}
			goto end;
		}

		nb_fd = ret;

		/* From here, the event is a metadata wait fd */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			if (pollfd == lttng_pipe_get_readfd(ctx->consumer_metadata_pipe)) {
				if (revents & LPOLLIN) {
					ssize_t pipe_len;

					pipe_len = lttng_pipe_read(ctx->consumer_metadata_pipe,
							&stream, sizeof(stream));
					if (pipe_len < sizeof(stream)) {
						if (pipe_len < 0) {
							PERROR("read metadata stream");
						}
						/*
						 * Remove the pipe from the poll set and continue the loop
						 * since their might be data to consume.
						 */
						lttng_poll_del(&events,
								lttng_pipe_get_readfd(ctx->consumer_metadata_pipe));
						lttng_pipe_read_close(ctx->consumer_metadata_pipe);
						continue;
					}

					/* A NULL stream means that the state has changed. */
					if (stream == NULL) {
						/* Check for deleted streams. */
						validate_endpoint_status_metadata_stream(&events);
						goto restart;
					}

					DBG("Adding metadata stream %d to poll set",
							stream->wait_fd);

					/* Add metadata stream to the global poll events list */
					lttng_poll_add(&events, stream->wait_fd,
							LPOLLIN | LPOLLPRI | LPOLLHUP);
				} else if (revents & (LPOLLERR | LPOLLHUP)) {
					DBG("Metadata thread pipe hung up");
					/*
					 * Remove the pipe from the poll set and continue the loop
					 * since their might be data to consume.
					 */
					lttng_poll_del(&events,
							lttng_pipe_get_readfd(ctx->consumer_metadata_pipe));
					lttng_pipe_read_close(ctx->consumer_metadata_pipe);
					continue;
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto end;
				}

				/* Handle other stream */
				continue;
			}

			rcu_read_lock();
			{
				uint64_t tmp_id = (uint64_t) pollfd;

				lttng_ht_lookup(metadata_ht, &tmp_id, &iter);
			}
			node = lttng_ht_iter_get_node_u64(&iter);
			assert(node);

			stream = caa_container_of(node, struct lttng_consumer_stream,
					node);

			if (revents & (LPOLLIN | LPOLLPRI)) {
				/* Get the data out of the metadata file descriptor */
				DBG("Metadata available on fd %d", pollfd);
				assert(stream->wait_fd == pollfd);

				do {
					health_code_update();

					len = ctx->on_buffer_ready(stream, ctx);
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
				if (!stream->hangup_flush_done
						&& (consumer_data.type == LTTNG_CONSUMER32_UST
							|| consumer_data.type == LTTNG_CONSUMER64_UST)) {
					DBG("Attempting to flush and consume the UST buffers");
					lttng_ustconsumer_on_stream_hangup(stream);

					/* We just flushed the stream now read it. */
					do {
						health_code_update();

						len = ctx->on_buffer_ready(stream, ctx);
						/*
						 * We don't check the return value here since if we get
						 * a negative len, it means an error occurred thus we
						 * simply remove it from the poll set and free the
						 * stream.
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
				rcu_read_unlock();
				goto end;
			}
			/* Release RCU lock for the stream looked up */
			rcu_read_unlock();
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
	return NULL;
}

/*
 * This thread polls the fds in the set to consume the data and write
 * it to tracefile if necessary.
 */
void *consumer_thread_data_poll(void *data)
{
	int num_rdy, num_hup, high_prio, ret, i, err = -1;
	struct pollfd *pollfd = NULL;
	/* local view of the streams */
	struct lttng_consumer_stream **local_stream = NULL, *new_stream = NULL;
	/* local view of consumer_data.fds_count */
	int nb_fd = 0;
	struct lttng_consumer_local_data *ctx = data;
	ssize_t len;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_DATA);

	if (testpoint(consumerd_thread_data)) {
		goto error_testpoint;
	}

	health_code_update();

	local_stream = zmalloc(sizeof(struct lttng_consumer_stream *));
	if (local_stream == NULL) {
		PERROR("local_stream malloc");
		goto end;
	}

	while (1) {
		health_code_update();

		high_prio = 0;
		num_hup = 0;

		/*
		 * the fds set has been updated, we need to update our
		 * local array as well
		 */
		pthread_mutex_lock(&consumer_data.lock);
		if (consumer_data.need_update) {
			free(pollfd);
			pollfd = NULL;

			free(local_stream);
			local_stream = NULL;

			/*
			 * Allocate for all fds +1 for the consumer_data_pipe and +1 for
			 * wake up pipe.
			 */
			pollfd = zmalloc((consumer_data.stream_count + 2) * sizeof(struct pollfd));
			if (pollfd == NULL) {
				PERROR("pollfd malloc");
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}

			local_stream = zmalloc((consumer_data.stream_count + 2) *
					sizeof(struct lttng_consumer_stream *));
			if (local_stream == NULL) {
				PERROR("local_stream malloc");
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}
			ret = update_poll_array(ctx, &pollfd, local_stream,
					data_ht);
			if (ret < 0) {
				ERR("Error in allocating pollfd or local_outfds");
				lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_POLL_ERROR);
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}
			nb_fd = ret;
			consumer_data.need_update = 0;
		}
		pthread_mutex_unlock(&consumer_data.lock);

		/* No FDs and consumer_quit, consumer_cleanup the thread */
		if (nb_fd == 0 && CMM_LOAD_SHARED(consumer_quit) == 1) {
			err = 0;	/* All is OK */
			goto end;
		}
		/* poll on the array of fds */
	restart:
		DBG("polling on %d fd", nb_fd + 2);
		if (testpoint(consumerd_thread_data_poll)) {
			goto end;
		}
		health_poll_entry();
		num_rdy = poll(pollfd, nb_fd + 2, -1);
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
					&new_stream, sizeof(new_stream));
			if (pipe_readlen < sizeof(new_stream)) {
				PERROR("Consumer data pipe");
				/* Continue so we can at least handle the current stream(s). */
				continue;
			}

			/*
			 * If the stream is NULL, just ignore it. It's also possible that
			 * the sessiond poll thread changed the consumer_quit state and is
			 * waking us up to test it.
			 */
			if (new_stream == NULL) {
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

			pipe_readlen = lttng_pipe_read(ctx->consumer_wakeup_pipe, &dummy,
					sizeof(dummy));
			if (pipe_readlen < 0) {
				PERROR("Consumer data wakeup pipe");
			}
			/* We've been awakened to handle stream(s). */
			ctx->has_wakeup = 0;
		}

		/* Take care of high priority channels first. */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			if (local_stream[i] == NULL) {
				continue;
			}
			if (pollfd[i].revents & POLLPRI) {
				DBG("Urgent read on fd %d", pollfd[i].fd);
				high_prio = 1;
				len = ctx->on_buffer_ready(local_stream[i], ctx);
				/* it's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					/* Clean the stream and free it. */
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = NULL;
				} else if (len > 0) {
					local_stream[i]->data_read = 1;
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

			if (local_stream[i] == NULL) {
				continue;
			}
			if ((pollfd[i].revents & POLLIN) ||
					local_stream[i]->hangup_flush_done ||
					local_stream[i]->has_data) {
				DBG("Normal read on fd %d", pollfd[i].fd);
				len = ctx->on_buffer_ready(local_stream[i], ctx);
				/* it's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					/* Clean the stream and free it. */
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = NULL;
				} else if (len > 0) {
					local_stream[i]->data_read = 1;
				}
			}
		}

		/* Handle hangup and errors */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			if (local_stream[i] == NULL) {
				continue;
			}
			if (!local_stream[i]->hangup_flush_done
					&& (pollfd[i].revents & (POLLHUP | POLLERR | POLLNVAL))
					&& (consumer_data.type == LTTNG_CONSUMER32_UST
						|| consumer_data.type == LTTNG_CONSUMER64_UST)) {
				DBG("fd %d is hup|err|nval. Attempting flush and read.",
						pollfd[i].fd);
				lttng_ustconsumer_on_stream_hangup(local_stream[i]);
				/* Attempt read again, for the data we just flushed. */
				local_stream[i]->data_read = 1;
			}
			/*
			 * If the poll flag is HUP/ERR/NVAL and we have
			 * read no data in this pass, we can remove the
			 * stream from its hash table.
			 */
			if ((pollfd[i].revents & POLLHUP)) {
				DBG("Polling fd %d tells it has hung up.", pollfd[i].fd);
				if (!local_stream[i]->data_read) {
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = NULL;
					num_hup++;
				}
			} else if (pollfd[i].revents & POLLERR) {
				ERR("Error returned in polling fd %d.", pollfd[i].fd);
				if (!local_stream[i]->data_read) {
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = NULL;
					num_hup++;
				}
			} else if (pollfd[i].revents & POLLNVAL) {
				ERR("Polling fd %d tells fd is not open.", pollfd[i].fd);
				if (!local_stream[i]->data_read) {
					consumer_del_stream(local_stream[i], data_ht);
					local_stream[i] = NULL;
					num_hup++;
				}
			}
			if (local_stream[i] != NULL) {
				local_stream[i]->data_read = 0;
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
	return NULL;
}

/*
 * Close wake-up end of each stream belonging to the channel. This will
 * allow the poll() on the stream read-side to detect when the
 * write-side (application) finally closes them.
 */
static
void consumer_close_channel_streams(struct lttng_consumer_channel *channel)
{
	struct lttng_ht *ht;
	struct lttng_consumer_stream *stream;
	struct lttng_ht_iter iter;

	ht = consumer_data.stream_per_chan_id_ht;

	rcu_read_lock();
	cds_lfht_for_each_entry_duplicate(ht->ht,
			ht->hash_fct(&channel->key, lttng_ht_seed),
			ht->match_fct, &channel->key,
			&iter.iter, stream, node_channel_id.node) {
		/*
		 * Protect against teardown with mutex.
		 */
		pthread_mutex_lock(&stream->lock);
		if (cds_lfht_is_node_deleted(&stream->node.node)) {
			goto next;
		}
		switch (consumer_data.type) {
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
			assert(0);
		}
	next:
		pthread_mutex_unlock(&stream->lock);
	}
	rcu_read_unlock();
}

static void destroy_channel_ht(struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *channel;
	int ret;

	if (ht == NULL) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(ht->ht, &iter.iter, channel, wait_fd_node.node) {
		ret = lttng_ht_del(ht, &iter);
		assert(ret != 0);
	}
	rcu_read_unlock();

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
	struct lttng_consumer_channel *chan = NULL;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct lttng_poll_event events;
	struct lttng_consumer_local_data *ctx = data;
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

	while (1) {
restart:
		health_code_update();
		DBG("Channel poll wait");
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG("Channel poll return from wait with %d fd(s)",
				LTTNG_POLL_GETNB(&events));
		health_poll_exit();
		DBG("Channel event caught in thread");
		if (ret < 0) {
			if (errno == EINTR) {
				ERR("Poll EINTR caught");
				goto restart;
			}
			if (LTTNG_POLL_GETNB(&events) == 0) {
				err = 0;	/* All is OK */
			}
			goto end;
		}

		nb_fd = ret;

		/* From here, the event is a channel wait fd */
		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			if (pollfd == ctx->consumer_channel_pipe[0]) {
				if (revents & LPOLLIN) {
					enum consumer_channel_action action;
					uint64_t key;

					ret = read_channel_pipe(ctx, &chan, &key, &action);
					if (ret <= 0) {
						if (ret < 0) {
							ERR("Error reading channel pipe");
						}
						lttng_poll_del(&events, ctx->consumer_channel_pipe[0]);
						continue;
					}

					switch (action) {
					case CONSUMER_CHANNEL_ADD:
						DBG("Adding channel %d to poll set",
							chan->wait_fd);

						lttng_ht_node_init_u64(&chan->wait_fd_node,
							chan->wait_fd);
						rcu_read_lock();
						lttng_ht_add_unique_u64(channel_ht,
								&chan->wait_fd_node);
						rcu_read_unlock();
						/* Add channel to the global poll events list */
						lttng_poll_add(&events, chan->wait_fd,
								LPOLLERR | LPOLLHUP);
						break;
					case CONSUMER_CHANNEL_DEL:
					{
						/*
						 * This command should never be called if the channel
						 * has streams monitored by either the data or metadata
						 * thread. The consumer only notify this thread with a
						 * channel del. command if it receives a destroy
						 * channel command from the session daemon that send it
						 * if a command prior to the GET_CHANNEL failed.
						 */

						rcu_read_lock();
						chan = consumer_find_channel(key);
						if (!chan) {
							rcu_read_unlock();
							ERR("UST consumer get channel key %" PRIu64 " not found for del channel", key);
							break;
						}
						lttng_poll_del(&events, chan->wait_fd);
						iter.iter.node = &chan->wait_fd_node.node;
						ret = lttng_ht_del(channel_ht, &iter);
						assert(ret == 0);

						switch (consumer_data.type) {
						case LTTNG_CONSUMER_KERNEL:
							break;
						case LTTNG_CONSUMER32_UST:
						case LTTNG_CONSUMER64_UST:
							health_code_update();
							/* Destroy streams that might have been left in the stream list. */
							clean_channel_stream_list(chan);
							break;
						default:
							ERR("Unknown consumer_data type");
							assert(0);
						}

						/*
						 * Release our own refcount. Force channel deletion even if
						 * streams were not initialized.
						 */
						if (!uatomic_sub_return(&chan->refcount, 1)) {
							consumer_del_channel(chan);
						}
						rcu_read_unlock();
						goto restart;
					}
					case CONSUMER_CHANNEL_QUIT:
						/*
						 * Remove the pipe from the poll set and continue the loop
						 * since their might be data to consume.
						 */
						lttng_poll_del(&events, ctx->consumer_channel_pipe[0]);
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
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto end;
				}

				/* Handle other stream */
				continue;
			}

			rcu_read_lock();
			{
				uint64_t tmp_id = (uint64_t) pollfd;

				lttng_ht_lookup(channel_ht, &tmp_id, &iter);
			}
			node = lttng_ht_iter_get_node_u64(&iter);
			assert(node);

			chan = caa_container_of(node, struct lttng_consumer_channel,
					wait_fd_node);

			/* Check for error event */
			if (revents & (LPOLLERR | LPOLLHUP)) {
				DBG("Channel fd %d is hup|err.", pollfd);

				lttng_poll_del(&events, chan->wait_fd);
				ret = lttng_ht_del(channel_ht, &iter);
				assert(ret == 0);

				/*
				 * This will close the wait fd for each stream associated to
				 * this channel AND monitored by the data/metadata thread thus
				 * will be clean by the right thread.
				 */
				consumer_close_channel_streams(chan);

				/* Release our own refcount */
				if (!uatomic_sub_return(&chan->refcount, 1)
						&& !uatomic_read(&chan->nb_init_stream_left)) {
					consumer_del_channel(chan);
				}
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				rcu_read_unlock();
				goto end;
			}

			/* Release RCU lock for the channel looked up */
			rcu_read_unlock();
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
	return NULL;
}

static int set_metadata_socket(struct lttng_consumer_local_data *ctx,
		struct pollfd *sockpoll, int client_socket)
{
	int ret;

	assert(ctx);
	assert(sockpoll);

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
	struct lttng_consumer_local_data *ctx = data;

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

	while (1) {
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
			err = 0;	/* All is OK */
			goto end;
		}
		DBG("received command on sock");
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

	notify_channel_pipe(ctx, NULL, -1, CONSUMER_CHANNEL_QUIT);

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
	return NULL;
}

ssize_t lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	ssize_t ret;

	pthread_mutex_lock(&stream->lock);
	if (stream->metadata_flag) {
		pthread_mutex_lock(&stream->metadata_rdv_lock);
	}

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		ret = lttng_kconsumer_read_subbuffer(stream, ctx);
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		ret = lttng_ustconsumer_read_subbuffer(stream, ctx);
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		ret = -ENOSYS;
		break;
	}

	if (stream->metadata_flag) {
		pthread_cond_broadcast(&stream->metadata_rdv);
		pthread_mutex_unlock(&stream->metadata_rdv_lock);
	}
	pthread_mutex_unlock(&stream->lock);
	return ret;
}

int lttng_consumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_on_recv_stream(stream);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_on_recv_stream(stream);
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		return -ENOSYS;
	}
}

/*
 * Allocate and set consumer data hash tables.
 */
int lttng_consumer_init(void)
{
	consumer_data.channel_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!consumer_data.channel_ht) {
		goto error;
	}

	consumer_data.relayd_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!consumer_data.relayd_ht) {
		goto error;
	}

	consumer_data.stream_list_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!consumer_data.stream_list_ht) {
		goto error;
	}

	consumer_data.stream_per_chan_id_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!consumer_data.stream_per_chan_id_ht) {
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
 void consumer_add_relayd_socket(uint64_t net_seq_idx, int sock_type,
		struct lttng_consumer_local_data *ctx, int sock,
		struct pollfd *consumer_sockpoll,
		struct lttcomm_relayd_sock *relayd_sock, uint64_t sessiond_id,
		uint64_t relayd_session_id)
{
	int fd = -1, ret = -1, relayd_created = 0;
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct consumer_relayd_sock_pair *relayd = NULL;

	assert(ctx);
	assert(relayd_sock);

	DBG("Consumer adding relayd socket (idx: %" PRIu64 ")", net_seq_idx);

	/* Get relayd reference if exists. */
	relayd = consumer_find_relayd(net_seq_idx);
	if (relayd == NULL) {
		assert(sock_type == LTTNG_STREAM_CONTROL);
		/* Not found. Allocate one. */
		relayd = consumer_allocate_relayd_sock_pair(net_seq_idx);
		if (relayd == NULL) {
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
		assert(sock_type != LTTNG_STREAM_CONTROL);
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
		fd = -1;	/* Just in case it gets set with an invalid value. */

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
		lttcomm_copy_sock(&relayd->control_sock.sock, &relayd_sock->sock);
		ret = lttcomm_create_sock(&relayd->control_sock.sock);
		/* Handle create_sock error. */
		if (ret < 0) {
			ret_code = LTTCOMM_CONSUMERD_ENOMEM;
			goto error;
		}
		/*
		 * Close the socket created internally by
		 * lttcomm_create_sock, so we can replace it by the one
		 * received from sessiond.
		 */
		if (close(relayd->control_sock.sock.fd)) {
			PERROR("close");
		}

		/* Assign new file descriptor */
		relayd->control_sock.sock.fd = fd;
		fd = -1;	/* For error path */
		/* Assign version values. */
		relayd->control_sock.major = relayd_sock->major;
		relayd->control_sock.minor = relayd_sock->minor;

		relayd->relayd_session_id = relayd_session_id;

		break;
	case LTTNG_STREAM_DATA:
		/* Copy received lttcomm socket */
		lttcomm_copy_sock(&relayd->data_sock.sock, &relayd_sock->sock);
		ret = lttcomm_create_sock(&relayd->data_sock.sock);
		/* Handle create_sock error. */
		if (ret < 0) {
			ret_code = LTTCOMM_CONSUMERD_ENOMEM;
			goto error;
		}
		/*
		 * Close the socket created internally by
		 * lttcomm_create_sock, so we can replace it by the one
		 * received from sessiond.
		 */
		if (close(relayd->data_sock.sock.fd)) {
			PERROR("close");
		}

		/* Assign new file descriptor */
		relayd->data_sock.sock.fd = fd;
		fd = -1;	/* for eventual error paths */
		/* Assign version values. */
		relayd->data_sock.major = relayd_sock->major;
		relayd->data_sock.minor = relayd_sock->minor;
		break;
	default:
		ERR("Unknown relayd socket type (%d)", sock_type);
		ret_code = LTTCOMM_CONSUMERD_FATAL;
		goto error;
	}

	DBG("Consumer %s socket created successfully with net idx %" PRIu64 " (fd: %d)",
			sock_type == LTTNG_STREAM_CONTROL ? "control" : "data",
			relayd->net_seq_idx, fd);

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
 * Try to lock the stream mutex.
 *
 * On success, 1 is returned else 0 indicating that the mutex is NOT lock.
 */
static int stream_try_lock(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);

	/*
	 * Try to lock the stream mutex. On failure, we know that the stream is
	 * being used else where hence there is data still being extracted.
	 */
	ret = pthread_mutex_trylock(&stream->lock);
	if (ret) {
		/* For both EBUSY and EINVAL error, the mutex is NOT locked. */
		ret = 0;
		goto end;
	}

	ret = 1;

end:
	return ret;
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
	struct consumer_relayd_sock_pair *relayd = NULL;

	/* Iterate over all relayd since they are indexed by net_seq_idx. */
	cds_lfht_for_each_entry(consumer_data.relayd_ht->ht, &iter.iter, relayd,
			node.node) {
		/*
		 * Check by sessiond id which is unique here where the relayd session
		 * id might not be when having multiple relayd.
		 */
		if (relayd->sessiond_session_id == id) {
			/* Found the relayd. There can be only one per id. */
			goto found;
		}
	}

	return NULL;

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
	struct consumer_relayd_sock_pair *relayd = NULL;
	int (*data_pending)(struct lttng_consumer_stream *);

	DBG("Consumer data pending command on session id %" PRIu64, id);

	rcu_read_lock();
	pthread_mutex_lock(&consumer_data.lock);

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		data_pending = lttng_kconsumer_data_pending;
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		data_pending = lttng_ustconsumer_data_pending;
		break;
	default:
		ERR("Unknown consumer data type");
		assert(0);
	}

	/* Ease our life a bit */
	ht = consumer_data.stream_list_ht;

	relayd = find_relayd_by_session_id(id);
	if (relayd) {
		/* Send init command for data pending. */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_begin_data_pending(&relayd->control_sock,
				relayd->relayd_session_id);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
			/* Communication error thus the relayd so no data pending. */
			goto data_not_pending;
		}
	}

	cds_lfht_for_each_entry_duplicate(ht->ht,
			ht->hash_fct(&id, lttng_ht_seed),
			ht->match_fct, &id,
			&iter.iter, stream, node_session_id.node) {
		/* If this call fails, the stream is being used hence data pending. */
		ret = stream_try_lock(stream);
		if (!ret) {
			goto data_pending;
		}

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

		/* Relayd check */
		if (relayd) {
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			if (stream->metadata_flag) {
				ret = relayd_quiescent_control(&relayd->control_sock,
						stream->relayd_stream_id);
			} else {
				ret = relayd_data_pending(&relayd->control_sock,
						stream->relayd_stream_id,
						stream->next_net_seq_num - 1);
			}
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
			if (ret == 1) {
				pthread_mutex_unlock(&stream->lock);
				goto data_pending;
			}
		}
		pthread_mutex_unlock(&stream->lock);
	}

	if (relayd) {
		unsigned int is_data_inflight = 0;

		/* Send init command for data pending. */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_end_data_pending(&relayd->control_sock,
				relayd->relayd_session_id, &is_data_inflight);
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		if (ret < 0) {
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
	pthread_mutex_unlock(&consumer_data.lock);
	rcu_read_unlock();
	return 0;

data_pending:
	/* Data is still being extracted from buffers. */
	pthread_mutex_unlock(&consumer_data.lock);
	rcu_read_unlock();
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
	msg.ret_code = ret_code;

	return lttcomm_send_unix_sock(sock, &msg, sizeof(msg));
}

/*
 * Send a channel status message to the sessiond daemon.
 *
 * Return the sendmsg() return value.
 */
int consumer_send_status_channel(int sock,
		struct lttng_consumer_channel *channel)
{
	struct lttcomm_consumer_status_channel msg;

	assert(sock >= 0);

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
		unsigned long produced_pos, uint64_t nb_packets_per_stream,
		uint64_t max_sb_size)
{
	unsigned long start_pos;

	if (!nb_packets_per_stream) {
		return consumed_pos;	/* Grab everything */
	}
	start_pos = produced_pos - offset_align_floor(produced_pos, max_sb_size);
	start_pos -= max_sb_size * nb_packets_per_stream;
	if ((long) (start_pos - consumed_pos) < 0) {
		return consumed_pos;	/* Grab everything */
	}
	return start_pos;
}
