/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

#include <common/common.h>
#include <common/relayd/relayd.h>
#include <common/ust-consumer/ust-consumer.h>

#include "consumer-stream.h"

/*
 * RCU call to free stream. MUST only be used with call_rcu().
 */
static void free_stream_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node =
		caa_container_of(head, struct lttng_ht_node_u64, head);
	struct lttng_consumer_stream *stream =
		caa_container_of(node, struct lttng_consumer_stream, node);

	pthread_mutex_destroy(&stream->lock);
	free(stream);
}

/*
 * Close stream on the relayd side. This call can destroy a relayd if the
 * conditions are met.
 *
 * A RCU read side lock MUST be acquired if the relayd object was looked up in
 * a hash table before calling this.
 */
void consumer_stream_relayd_close(struct lttng_consumer_stream *stream,
		struct consumer_relayd_sock_pair *relayd)
{
	int ret;

	assert(stream);
	assert(relayd);

	uatomic_dec(&relayd->refcount);
	assert(uatomic_read(&relayd->refcount) >= 0);

	/* Closing streams requires to lock the control socket. */
	pthread_mutex_lock(&relayd->ctrl_sock_mutex);
	ret = relayd_send_close_stream(&relayd->control_sock,
			stream->relayd_stream_id,
			stream->next_net_seq_num - 1);
	pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	if (ret < 0) {
		DBG("Unable to close stream on the relayd. Continuing");
		/*
		 * Continue here. There is nothing we can do for the relayd.
		 * Chances are that the relayd has closed the socket so we just
		 * continue cleaning up.
		 */
	}

	/* Both conditions are met, we destroy the relayd. */
	if (uatomic_read(&relayd->refcount) == 0 &&
			uatomic_read(&relayd->destroy_flag)) {
		consumer_destroy_relayd(relayd);
	}
}

/*
 * Close stream's file descriptors and, if needed, close stream also on the
 * relayd side.
 *
 * The consumer data lock MUST be acquired.
 * The stream lock MUST be acquired.
 */
void consumer_stream_close(struct lttng_consumer_stream *stream)
{
	int ret;
	struct consumer_relayd_sock_pair *relayd;

	assert(stream);

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		if (stream->mmap_base != NULL) {
			ret = munmap(stream->mmap_base, stream->mmap_len);
			if (ret != 0) {
				PERROR("munmap");
			}
		}

		if (stream->wait_fd >= 0) {
			ret = close(stream->wait_fd);
			if (ret) {
				PERROR("close");
			}
		}
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		lttng_ustconsumer_del_stream(stream);
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
	}

	/* Close output fd. Could be a socket or local file at this point. */
	if (stream->out_fd >= 0) {
		ret = close(stream->out_fd);
		if (ret) {
			PERROR("close");
		}
	}

	/* Check and cleanup relayd if needed. */
	rcu_read_lock();
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd != NULL) {
		consumer_stream_relayd_close(stream, relayd);
	}
	rcu_read_unlock();
}

/*
 * Delete the stream from all possible hash tables.
 *
 * The consumer data lock MUST be acquired.
 * The stream lock MUST be acquired.
 */
void consumer_stream_delete(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(stream);

	rcu_read_lock();

	if (ht) {
		iter.iter.node = &stream->node.node;
		ret = lttng_ht_del(ht, &iter);
		assert(!ret);
	}

	/* Delete from stream per channel ID hash table. */
	iter.iter.node = &stream->node_channel_id.node;
	/*
	 * The returned value is of no importance. Even if the node is NOT in the
	 * hash table, we continue since we may have been called by a code path
	 * that did not add the stream to a (all) hash table. Same goes for the
	 * next call ht del call.
	 */
	(void) lttng_ht_del(consumer_data.stream_per_chan_id_ht, &iter);

	/* Delete from the global stream list. */
	iter.iter.node = &stream->node_session_id.node;
	/* See the previous ht del on why we ignore the returned value. */
	(void) lttng_ht_del(consumer_data.stream_list_ht, &iter);

	rcu_read_unlock();

	/* Decrement the stream count of the global consumer data. */
	assert(consumer_data.stream_count > 0);
	consumer_data.stream_count--;
}

/*
 * Free the given stream within a RCU call.
 */
void consumer_stream_free(struct lttng_consumer_stream *stream)
{
	assert(stream);

	call_rcu(&stream->node.head, free_stream_rcu);
}

/*
 * Destroy a stream completely. This will delete, close and free the stream.
 * Once return, the stream is NO longer usable. Its channel may get destroyed
 * if conditions are met.
 *
 * This MUST be called WITHOUT the consumer data and stream lock acquired.
 */
void consumer_stream_destroy(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
{
	struct lttng_consumer_channel *free_chan = NULL;

	assert(stream);

	DBG("Consumer stream destroy - wait_fd: %d", stream->wait_fd);

	pthread_mutex_lock(&consumer_data.lock);
	pthread_mutex_lock(&stream->lock);

	/* Remove every reference of the stream in the consumer. */
	consumer_stream_delete(stream, ht);

	/* Close down everything including the relayd if one. */
	consumer_stream_close(stream);

	/* Update refcount of channel and see if we need to destroy it. */
	if (!uatomic_sub_return(&stream->chan->refcount, 1)
			&& !uatomic_read(&stream->chan->nb_init_stream_left)) {
		free_chan = stream->chan;
	}

	/* Indicates that the consumer data state MUST be updated after this. */
	consumer_data.need_update = 1;

	pthread_mutex_unlock(&stream->lock);
	pthread_mutex_unlock(&consumer_data.lock);

	if (free_chan) {
		consumer_del_channel(free_chan);
	}

	/* Free stream within a RCU call. */
	consumer_stream_free(stream);
}
