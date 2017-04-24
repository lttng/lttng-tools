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

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <unistd.h>

#include <common/common.h>
#include <common/index/index.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/relayd/relayd.h>
#include <common/ust-consumer/ust-consumer.h>
#include <common/utils.h>

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

	if (stream->sent_to_relayd) {
		uatomic_dec(&relayd->refcount);
		assert(uatomic_read(&relayd->refcount) >= 0);
	}

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
	stream->net_seq_idx = (uint64_t) -1ULL;
	stream->sent_to_relayd = 0;
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
			stream->wait_fd = -1;
		}
		if (stream->chan->output == CONSUMER_CHANNEL_SPLICE) {
			utils_close_pipe(stream->splice_pipe);
		}
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
	{
		/*
		 * Special case for the metadata since the wait fd is an internal pipe
		 * polled in the metadata thread.
		 */
		if (stream->metadata_flag && stream->chan->monitor) {
			int rpipe = stream->ust_metadata_poll_pipe[0];

			/*
			 * This will stop the channel timer if one and close the write side
			 * of the metadata poll pipe.
			 */
			lttng_ustconsumer_close_metadata(stream->chan);
			if (rpipe >= 0) {
				ret = close(rpipe);
				if (ret < 0) {
					PERROR("closing metadata pipe read side");
				}
				stream->ust_metadata_poll_pipe[0] = -1;
			}
		}
		break;
	}
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
		stream->out_fd = -1;
	}

	if (stream->index_file) {
		lttng_index_file_put(stream->index_file);
		stream->index_file = NULL;
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
	/* Should NEVER be called not in monitor mode. */
	assert(stream->chan->monitor);

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

	if (!stream->metadata_flag) {
		/* Decrement the stream count of the global consumer data. */
		assert(consumer_data.stream_count > 0);
		consumer_data.stream_count--;
	}
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
 * Destroy the stream's buffers of the tracer.
 */
void consumer_stream_destroy_buffers(struct lttng_consumer_stream *stream)
{
	assert(stream);

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		lttng_ustconsumer_del_stream(stream);
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
	}
}

/*
 * Destroy and close a already created stream.
 */
static void destroy_close_stream(struct lttng_consumer_stream *stream)
{
	assert(stream);

	DBG("Consumer stream destroy monitored key: %" PRIu64, stream->key);

	/* Destroy tracer buffers of the stream. */
	consumer_stream_destroy_buffers(stream);
	/* Close down everything including the relayd if one. */
	consumer_stream_close(stream);
}

/*
 * Decrement the stream's channel refcount and if down to 0, return the channel
 * pointer so it can be destroyed by the caller or NULL if not.
 */
static struct lttng_consumer_channel *unref_channel(
		struct lttng_consumer_stream *stream)
{
	struct lttng_consumer_channel *free_chan = NULL;

	assert(stream);
	assert(stream->chan);

	/* Update refcount of channel and see if we need to destroy it. */
	if (!uatomic_sub_return(&stream->chan->refcount, 1)
			&& !uatomic_read(&stream->chan->nb_init_stream_left)) {
		free_chan = stream->chan;
	}

	return free_chan;
}

/*
 * Destroy a stream completely. This will delete, close and free the stream.
 * Once return, the stream is NO longer usable. Its channel may get destroyed
 * if conditions are met for a monitored stream.
 *
 * This MUST be called WITHOUT the consumer data and stream lock acquired if
 * the stream is in _monitor_ mode else it does not matter.
 */
void consumer_stream_destroy(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
{
	assert(stream);

	/* Stream is in monitor mode. */
	if (stream->monitor) {
		struct lttng_consumer_channel *free_chan = NULL;

		/*
		 * This means that the stream was successfully removed from the streams
		 * list of the channel and sent to the right thread managing this
		 * stream thus being globally visible.
		 */
		if (stream->globally_visible) {
			pthread_mutex_lock(&consumer_data.lock);
			pthread_mutex_lock(&stream->chan->lock);
			pthread_mutex_lock(&stream->lock);
			/* Remove every reference of the stream in the consumer. */
			consumer_stream_delete(stream, ht);

			destroy_close_stream(stream);

			/* Update channel's refcount of the stream. */
			free_chan = unref_channel(stream);

			/* Indicates that the consumer data state MUST be updated after this. */
			consumer_data.need_update = 1;

			pthread_mutex_unlock(&stream->lock);
			pthread_mutex_unlock(&stream->chan->lock);
			pthread_mutex_unlock(&consumer_data.lock);
		} else {
			/*
			 * If the stream is not visible globally, this needs to be done
			 * outside of the consumer data lock section.
			 */
			free_chan = unref_channel(stream);
		}

		if (free_chan) {
			consumer_del_channel(free_chan);
		}
	} else {
		destroy_close_stream(stream);
	}

	/* Free stream within a RCU call. */
	consumer_stream_free(stream);
}

/*
 * Write index of a specific stream either on the relayd or local disk.
 *
 * Return 0 on success or else a negative value.
 */
int consumer_stream_write_index(struct lttng_consumer_stream *stream,
		struct ctf_packet_index *element)
{
	int ret;

	assert(stream);
	assert(element);

	rcu_read_lock();
	if (stream->net_seq_idx != (uint64_t) -1ULL) {
		struct consumer_relayd_sock_pair *relayd;
		relayd = consumer_find_relayd(stream->net_seq_idx);
		if (relayd) {
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);
			ret = relayd_send_index(&relayd->control_sock, element,
				stream->relayd_stream_id, stream->next_net_seq_num - 1);
			pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
		} else {
			ERR("Stream %" PRIu64 " relayd ID %" PRIu64 " unknown. Can't write index.",
					stream->key, stream->net_seq_idx);
			ret = -1;
		}
	} else {
		if (lttng_index_file_write(stream->index_file, element)) {
			ret = -1;
		} else {
			ret = 0;
		}
	}
	if (ret < 0) {
		goto error;
	}

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Actually do the metadata sync using the given metadata stream.
 *
 * Return 0 on success else a negative value. ENODATA can be returned also
 * indicating that there is no metadata available for that stream.
 */
static int do_sync_metadata(struct lttng_consumer_stream *metadata,
		struct lttng_consumer_local_data *ctx)
{
	int ret;

	assert(metadata);
	assert(metadata->metadata_flag);
	assert(ctx);

	/*
	 * In UST, since we have to write the metadata from the cache packet
	 * by packet, we might need to start this procedure multiple times
	 * until all the metadata from the cache has been extracted.
	 */
	do {
		/*
		 * Steps :
		 * - Lock the metadata stream
		 * - Check if metadata stream node was deleted before locking.
		 *   - if yes, release and return success
		 * - Check if new metadata is ready (flush + snapshot pos)
		 * - If nothing : release and return.
		 * - Lock the metadata_rdv_lock
		 * - Unlock the metadata stream
		 * - cond_wait on metadata_rdv to wait the wakeup from the
		 *   metadata thread
		 * - Unlock the metadata_rdv_lock
		 */
		pthread_mutex_lock(&metadata->lock);

		/*
		 * There is a possibility that we were able to acquire a reference on the
		 * stream from the RCU hash table but between then and now, the node might
		 * have been deleted just before the lock is acquired. Thus, after locking,
		 * we make sure the metadata node has not been deleted which means that the
		 * buffers are closed.
		 *
		 * In that case, there is no need to sync the metadata hence returning a
		 * success return code.
		 */
		ret = cds_lfht_is_node_deleted(&metadata->node.node);
		if (ret) {
			ret = 0;
			goto end_unlock_mutex;
		}

		switch (ctx->type) {
		case LTTNG_CONSUMER_KERNEL:
			/*
			 * Empty the metadata cache and flush the current stream.
			 */
			ret = lttng_kconsumer_sync_metadata(metadata);
			break;
		case LTTNG_CONSUMER32_UST:
		case LTTNG_CONSUMER64_UST:
			/*
			 * Ask the sessiond if we have new metadata waiting and update the
			 * consumer metadata cache.
			 */
			ret = lttng_ustconsumer_sync_metadata(ctx, metadata);
			break;
		default:
			assert(0);
			ret = -1;
			break;
		}
		/*
		 * Error or no new metadata, we exit here.
		 */
		if (ret <= 0 || ret == ENODATA) {
			goto end_unlock_mutex;
		}

		/*
		 * At this point, new metadata have been flushed, so we wait on the
		 * rendez-vous point for the metadata thread to wake us up when it
		 * finishes consuming the metadata and continue execution.
		 */

		pthread_mutex_lock(&metadata->metadata_rdv_lock);

		/*
		 * Release metadata stream lock so the metadata thread can process it.
		 */
		pthread_mutex_unlock(&metadata->lock);

		/*
		 * Wait on the rendez-vous point. Once woken up, it means the metadata was
		 * consumed and thus synchronization is achieved.
		 */
		pthread_cond_wait(&metadata->metadata_rdv, &metadata->metadata_rdv_lock);
		pthread_mutex_unlock(&metadata->metadata_rdv_lock);
	} while (ret == EAGAIN);

	/* Success */
	return 0;

end_unlock_mutex:
	pthread_mutex_unlock(&metadata->lock);
	return ret;
}

/*
 * Synchronize the metadata using a given session ID. A successful acquisition
 * of a metadata stream will trigger a request to the session daemon and a
 * snapshot so the metadata thread can consume it.
 *
 * This function call is a rendez-vous point between the metadata thread and
 * the data thread.
 *
 * Return 0 on success or else a negative value.
 */
int consumer_stream_sync_metadata(struct lttng_consumer_local_data *ctx,
		uint64_t session_id)
{
	int ret;
	struct lttng_consumer_stream *stream = NULL;
	struct lttng_ht_iter iter;
	struct lttng_ht *ht;

	assert(ctx);

	/* Ease our life a bit. */
	ht = consumer_data.stream_list_ht;

	rcu_read_lock();

	/* Search the metadata associated with the session id of the given stream. */

	cds_lfht_for_each_entry_duplicate(ht->ht,
			ht->hash_fct(&session_id, lttng_ht_seed), ht->match_fct,
			&session_id, &iter.iter, stream, node_session_id.node) {
		if (!stream->metadata_flag) {
			continue;
		}

		ret = do_sync_metadata(stream, ctx);
		if (ret < 0) {
			goto end;
		}
	}

	/*
	 * Force return code to 0 (success) since ret might be ENODATA for instance
	 * which is not an error but rather that we should come back.
	 */
	ret = 0;

end:
	rcu_read_unlock();
	return ret;
}
