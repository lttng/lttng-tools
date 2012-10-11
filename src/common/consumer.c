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
#include <inttypes.h>

#include <common/common.h>
#include <common/utils.h>
#include <common/compat/poll.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/relayd.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/relayd/relayd.h>
#include <common/ust-consumer/ust-consumer.h>

#include "consumer.h"

struct lttng_consumer_global_data consumer_data = {
	.stream_count = 0,
	.need_update = 1,
	.type = LTTNG_CONSUMER_UNKNOWN,
};

/* timeout parameter, to control the polling thread grace period. */
int consumer_poll_timeout = -1;

/*
 * Flag to inform the polling thread to quit when all fd hung up. Updated by
 * the consumer_thread_receive_fds when it notices that all fds has hung up.
 * Also updated by the signal handler (consumer_should_exit()). Read by the
 * polling threads.
 */
volatile int consumer_quit = 0;

/*
 * Find a stream. The consumer_data.lock must be locked during this
 * call.
 */
static struct lttng_consumer_stream *consumer_find_stream(int key,
		struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct lttng_consumer_stream *stream = NULL;

	assert(ht);

	/* Negative keys are lookup failures */
	if (key < 0) {
		return NULL;
	}

	rcu_read_lock();

	lttng_ht_lookup(ht, (void *)((unsigned long) key), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node != NULL) {
		stream = caa_container_of(node, struct lttng_consumer_stream, node);
	}

	rcu_read_unlock();

	return stream;
}

void consumer_steal_stream_key(int key, struct lttng_ht *ht)
{
	struct lttng_consumer_stream *stream;

	rcu_read_lock();
	stream = consumer_find_stream(key, ht);
	if (stream) {
		stream->key = -1;
		/*
		 * We don't want the lookup to match, but we still need
		 * to iterate on this stream when iterating over the hash table. Just
		 * change the node key.
		 */
		stream->node.key = -1;
	}
	rcu_read_unlock();
}

static struct lttng_consumer_channel *consumer_find_channel(int key)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct lttng_consumer_channel *channel = NULL;

	/* Negative keys are lookup failures */
	if (key < 0) {
		return NULL;
	}

	rcu_read_lock();

	lttng_ht_lookup(consumer_data.channel_ht, (void *)((unsigned long) key),
			&iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node != NULL) {
		channel = caa_container_of(node, struct lttng_consumer_channel, node);
	}

	rcu_read_unlock();

	return channel;
}

static void consumer_steal_channel_key(int key)
{
	struct lttng_consumer_channel *channel;

	rcu_read_lock();
	channel = consumer_find_channel(key);
	if (channel) {
		channel->key = -1;
		/*
		 * We don't want the lookup to match, but we still need
		 * to iterate on this channel when iterating over the hash table. Just
		 * change the node key.
		 */
		channel->node.key = -1;
	}
	rcu_read_unlock();
}

static
void consumer_free_stream(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct lttng_consumer_stream *stream =
		caa_container_of(node, struct lttng_consumer_stream, node);

	free(stream);
}

static
void consumer_free_metadata_stream(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct lttng_consumer_stream *stream =
		caa_container_of(node, struct lttng_consumer_stream, waitfd_node);

	free(stream);
}

/*
 * RCU protected relayd socket pair free.
 */
static void consumer_rcu_free_relayd(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct consumer_relayd_sock_pair *relayd =
		caa_container_of(node, struct consumer_relayd_sock_pair, node);

	free(relayd);
}

/*
 * Destroy and free relayd socket pair object.
 *
 * This function MUST be called with the consumer_data lock acquired.
 */
static void destroy_relayd(struct consumer_relayd_sock_pair *relayd)
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
		/* We assume the relayd was already destroyed */
		return;
	}

	/* Close all sockets */
	pthread_mutex_lock(&relayd->ctrl_sock_mutex);
	(void) relayd_close(&relayd->control_sock);
	pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	(void) relayd_close(&relayd->data_sock);

	/* RCU free() call */
	call_rcu(&relayd->node.head, consumer_rcu_free_relayd);
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
		destroy_relayd(relayd);
	}
}

/*
 * Remove a stream from the global list protected by a mutex. This
 * function is also responsible for freeing its data structures.
 */
void consumer_del_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *free_chan = NULL;
	struct consumer_relayd_sock_pair *relayd;

	assert(stream);

	if (ht == NULL) {
		/* Means the stream was allocated but not successfully added */
		goto free_stream;
	}

	pthread_mutex_lock(&consumer_data.lock);

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		if (stream->mmap_base != NULL) {
			ret = munmap(stream->mmap_base, stream->mmap_len);
			if (ret != 0) {
				PERROR("munmap");
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
		goto end;
	}

	rcu_read_lock();
	iter.iter.node = &stream->node.node;
	ret = lttng_ht_del(ht, &iter);
	assert(!ret);

	rcu_read_unlock();

	if (consumer_data.stream_count <= 0) {
		goto end;
	}
	consumer_data.stream_count--;
	if (!stream) {
		goto end;
	}
	if (stream->out_fd >= 0) {
		ret = close(stream->out_fd);
		if (ret) {
			PERROR("close");
		}
	}
	if (stream->wait_fd >= 0 && !stream->wait_fd_is_copy) {
		ret = close(stream->wait_fd);
		if (ret) {
			PERROR("close");
		}
	}
	if (stream->shm_fd >= 0 && stream->wait_fd != stream->shm_fd) {
		ret = close(stream->shm_fd);
		if (ret) {
			PERROR("close");
		}
	}

	/* Check and cleanup relayd */
	rcu_read_lock();
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd != NULL) {
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
			destroy_relayd(relayd);
		}
	}
	rcu_read_unlock();

	uatomic_dec(&stream->chan->refcount);
	if (!uatomic_read(&stream->chan->refcount)
			&& !uatomic_read(&stream->chan->nb_init_streams)) {
		free_chan = stream->chan;
	}

end:
	consumer_data.need_update = 1;
	pthread_mutex_unlock(&consumer_data.lock);

	if (free_chan) {
		consumer_del_channel(free_chan);
	}

free_stream:
	call_rcu(&stream->node.head, consumer_free_stream);
}

struct lttng_consumer_stream *consumer_allocate_stream(
		int channel_key, int stream_key,
		int shm_fd, int wait_fd,
		enum lttng_consumer_stream_state state,
		uint64_t mmap_len,
		enum lttng_event_output output,
		const char *path_name,
		uid_t uid,
		gid_t gid,
		int net_index,
		int metadata_flag,
		int *alloc_ret)
{
	struct lttng_consumer_stream *stream;

	stream = zmalloc(sizeof(*stream));
	if (stream == NULL) {
		PERROR("malloc struct lttng_consumer_stream");
		*alloc_ret = -ENOMEM;
		goto end;
	}

	/*
	 * Get stream's channel reference. Needed when adding the stream to the
	 * global hash table.
	 */
	stream->chan = consumer_find_channel(channel_key);
	if (!stream->chan) {
		*alloc_ret = -ENOENT;
		ERR("Unable to find channel for stream %d", stream_key);
		goto error;
	}

	stream->key = stream_key;
	stream->shm_fd = shm_fd;
	stream->wait_fd = wait_fd;
	stream->out_fd = -1;
	stream->out_fd_offset = 0;
	stream->state = state;
	stream->mmap_len = mmap_len;
	stream->mmap_base = NULL;
	stream->output = output;
	stream->uid = uid;
	stream->gid = gid;
	stream->net_seq_idx = net_index;
	stream->metadata_flag = metadata_flag;
	strncpy(stream->path_name, path_name, sizeof(stream->path_name));
	stream->path_name[sizeof(stream->path_name) - 1] = '\0';
	lttng_ht_node_init_ulong(&stream->waitfd_node, stream->wait_fd);
	lttng_ht_node_init_ulong(&stream->node, stream->key);

	/*
	 * The cpu number is needed before using any ustctl_* actions. Ignored for
	 * the kernel so the value does not matter.
	 */
	pthread_mutex_lock(&consumer_data.lock);
	stream->cpu = stream->chan->cpucount++;
	pthread_mutex_unlock(&consumer_data.lock);

	DBG3("Allocated stream %s (key %d, shm_fd %d, wait_fd %d, mmap_len %llu,"
			" out_fd %d, net_seq_idx %d)", stream->path_name, stream->key,
			stream->shm_fd, stream->wait_fd,
			(unsigned long long) stream->mmap_len, stream->out_fd,
			stream->net_seq_idx);
	return stream;

error:
	free(stream);
end:
	return NULL;
}

/*
 * Add a stream to the global list protected by a mutex.
 */
int consumer_add_stream(struct lttng_consumer_stream *stream)
{
	int ret = 0;
	struct consumer_relayd_sock_pair *relayd;

	assert(stream);

	DBG3("Adding consumer stream %d", stream->key);

	pthread_mutex_lock(&consumer_data.lock);
	rcu_read_lock();

	lttng_ht_add_unique_ulong(consumer_data.stream_ht, &stream->node);

	/* Check and cleanup relayd */
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd != NULL) {
		uatomic_inc(&relayd->refcount);
	}

	/* Update channel refcount once added without error(s). */
	uatomic_inc(&stream->chan->refcount);

	/*
	 * When nb_init_streams reaches 0, we don't need to trigger any action in
	 * terms of destroying the associated channel, because the action that
	 * causes the count to become 0 also causes a stream to be added. The
	 * channel deletion will thus be triggered by the following removal of this
	 * stream.
	 */
	if (uatomic_read(&stream->chan->nb_init_streams) > 0) {
		uatomic_dec(&stream->chan->nb_init_streams);
	}

	/* Update consumer data once the node is inserted. */
	consumer_data.stream_count++;
	consumer_data.need_update = 1;

	rcu_read_unlock();
	pthread_mutex_unlock(&consumer_data.lock);

	return ret;
}

/*
 * Add relayd socket to global consumer data hashtable. RCU read side lock MUST
 * be acquired before calling this.
 */
static int add_relayd(struct consumer_relayd_sock_pair *relayd)
{
	int ret = 0;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	if (relayd == NULL) {
		ret = -1;
		goto end;
	}

	lttng_ht_lookup(consumer_data.relayd_ht,
			(void *)((unsigned long) relayd->net_seq_idx), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node != NULL) {
		/* Relayd already exist. Ignore the insertion */
		goto end;
	}
	lttng_ht_add_unique_ulong(consumer_data.relayd_ht, &relayd->node);

end:
	return ret;
}

/*
 * Allocate and return a consumer relayd socket.
 */
struct consumer_relayd_sock_pair *consumer_allocate_relayd_sock_pair(
		int net_seq_idx)
{
	struct consumer_relayd_sock_pair *obj = NULL;

	/* Negative net sequence index is a failure */
	if (net_seq_idx < 0) {
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
	lttng_ht_node_init_ulong(&obj->node, obj->net_seq_idx);
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
struct consumer_relayd_sock_pair *consumer_find_relayd(int key)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct consumer_relayd_sock_pair *relayd = NULL;

	/* Negative keys are lookup failures */
	if (key < 0) {
		goto error;
	}

	lttng_ht_lookup(consumer_data.relayd_ht, (void *)((unsigned long) key),
			&iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node != NULL) {
		relayd = caa_container_of(node, struct consumer_relayd_sock_pair, node);
	}

error:
	return relayd;
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
		outfd = relayd->control_sock.fd;
	} else {
		/* Set header with stream information */
		data_hdr.stream_id = htobe64(stream->relayd_stream_id);
		data_hdr.data_size = htobe32(data_size);
		data_hdr.padding_size = htobe32(padding);
		data_hdr.net_seq_num = htobe64(stream->next_net_seq_num++);
		/* Other fields are zeroed previously */

		ret = relayd_send_data_hdr(&relayd->data_sock, &data_hdr,
				sizeof(data_hdr));
		if (ret < 0) {
			goto error;
		}

		/* Set to go on data socket */
		outfd = relayd->data_sock.fd;
	}

error:
	return outfd;
}

/*
 * Update a stream according to what we just received.
 */
void consumer_change_stream_state(int stream_key,
		enum lttng_consumer_stream_state state)
{
	struct lttng_consumer_stream *stream;

	pthread_mutex_lock(&consumer_data.lock);
	stream = consumer_find_stream(stream_key, consumer_data.stream_ht);
	if (stream) {
		stream->state = state;
	}
	consumer_data.need_update = 1;
	pthread_mutex_unlock(&consumer_data.lock);
}

static
void consumer_free_channel(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct lttng_consumer_channel *channel =
		caa_container_of(node, struct lttng_consumer_channel, node);

	free(channel);
}

/*
 * Remove a channel from the global list protected by a mutex. This
 * function is also responsible for freeing its data structures.
 */
void consumer_del_channel(struct lttng_consumer_channel *channel)
{
	int ret;
	struct lttng_ht_iter iter;

	pthread_mutex_lock(&consumer_data.lock);

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

	if (channel->mmap_base != NULL) {
		ret = munmap(channel->mmap_base, channel->mmap_len);
		if (ret != 0) {
			PERROR("munmap");
		}
	}
	if (channel->wait_fd >= 0 && !channel->wait_fd_is_copy) {
		ret = close(channel->wait_fd);
		if (ret) {
			PERROR("close");
		}
	}
	if (channel->shm_fd >= 0 && channel->wait_fd != channel->shm_fd) {
		ret = close(channel->shm_fd);
		if (ret) {
			PERROR("close");
		}
	}

	call_rcu(&channel->node.head, consumer_free_channel);
end:
	pthread_mutex_unlock(&consumer_data.lock);
}

struct lttng_consumer_channel *consumer_allocate_channel(
		int channel_key,
		int shm_fd, int wait_fd,
		uint64_t mmap_len,
		uint64_t max_sb_size,
		unsigned int nb_init_streams)
{
	struct lttng_consumer_channel *channel;
	int ret;

	channel = zmalloc(sizeof(*channel));
	if (channel == NULL) {
		PERROR("malloc struct lttng_consumer_channel");
		goto end;
	}
	channel->key = channel_key;
	channel->shm_fd = shm_fd;
	channel->wait_fd = wait_fd;
	channel->mmap_len = mmap_len;
	channel->max_sb_size = max_sb_size;
	channel->refcount = 0;
	channel->nb_init_streams = nb_init_streams;
	lttng_ht_node_init_ulong(&channel->node, channel->key);

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		channel->mmap_base = NULL;
		channel->mmap_len = 0;
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		ret = lttng_ustconsumer_allocate_channel(channel);
		if (ret) {
			free(channel);
			return NULL;
		}
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		goto end;
	}
	DBG("Allocated channel (key %d, shm_fd %d, wait_fd %d, mmap_len %llu, max_sb_size %llu)",
			channel->key, channel->shm_fd, channel->wait_fd,
			(unsigned long long) channel->mmap_len,
			(unsigned long long) channel->max_sb_size);
end:
	return channel;
}

/*
 * Add a channel to the global list protected by a mutex.
 */
int consumer_add_channel(struct lttng_consumer_channel *channel)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	pthread_mutex_lock(&consumer_data.lock);
	/* Steal channel identifier, for UST */
	consumer_steal_channel_key(channel->key);
	rcu_read_lock();

	lttng_ht_lookup(consumer_data.channel_ht,
			(void *)((unsigned long) channel->key), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node != NULL) {
		/* Channel already exist. Ignore the insertion */
		goto end;
	}

	lttng_ht_add_unique_ulong(consumer_data.channel_ht, &channel->node);

end:
	rcu_read_unlock();
	pthread_mutex_unlock(&consumer_data.lock);

	return 0;
}

/*
 * Allocate the pollfd structure and the local view of the out fds to avoid
 * doing a lookup in the linked list and concurrency issues when writing is
 * needed. Called with consumer_data.lock held.
 *
 * Returns the number of fds in the structures.
 */
int consumer_update_poll_array(
		struct lttng_consumer_local_data *ctx, struct pollfd **pollfd,
		struct lttng_consumer_stream **local_stream)
{
	int i = 0;
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	DBG("Updating poll fd array");
	rcu_read_lock();
	cds_lfht_for_each_entry(consumer_data.stream_ht->ht, &iter.iter, stream,
			node.node) {
		if (stream->state != LTTNG_CONSUMER_ACTIVE_STREAM) {
			continue;
		}
		DBG("Active FD %d", stream->wait_fd);
		(*pollfd)[i].fd = stream->wait_fd;
		(*pollfd)[i].events = POLLIN | POLLPRI;
		local_stream[i] = stream;
		i++;
	}
	rcu_read_unlock();

	/*
	 * Insert the consumer_poll_pipe at the end of the array and don't
	 * increment i so nb_fd is the number of real FD.
	 */
	(*pollfd)[i].fd = ctx->consumer_poll_pipe[0];
	(*pollfd)[i].events = POLLIN | POLLPRI;
	return i;
}

/*
 * Poll on the should_quit pipe and the command socket return -1 on error and
 * should exit, 0 if data is available on the command socket
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
		goto exit;
	}
	if (consumer_sockpoll[0].revents & (POLLIN | POLLPRI)) {
		DBG("consumer_should_quit wake up");
		goto exit;
	}
	return 0;

exit:
	return -1;
}

/*
 * Set the error socket.
 */
void lttng_consumer_set_error_sock(
		struct lttng_consumer_local_data *ctx, int sock)
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
int lttng_consumer_send_error(
		struct lttng_consumer_local_data *ctx, int cmd)
{
	if (ctx->consumer_error_socket > 0) {
		return lttcomm_send_unix_sock(ctx->consumer_error_socket, &cmd,
				sizeof(enum lttcomm_sessiond_command));
	}

	return 0;
}

/*
 * Close all the tracefiles and stream fds, should be called when all instances
 * are destroyed.
 */
void lttng_consumer_cleanup(void)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;

	rcu_read_lock();

	/*
	 * close all outfd. Called when there are no more threads running (after
	 * joining on the threads), no need to protect list iteration with mutex.
	 */
	cds_lfht_for_each_entry(consumer_data.stream_ht->ht, &iter.iter, node,
			node) {
		struct lttng_consumer_stream *stream =
			caa_container_of(node, struct lttng_consumer_stream, node);
		consumer_del_stream(stream, consumer_data.stream_ht);
	}

	cds_lfht_for_each_entry(consumer_data.channel_ht->ht, &iter.iter, node,
			node) {
		struct lttng_consumer_channel *channel =
			caa_container_of(node, struct lttng_consumer_channel, node);
		consumer_del_channel(channel);
	}

	rcu_read_unlock();

	lttng_ht_destroy(consumer_data.stream_ht);
	lttng_ht_destroy(consumer_data.channel_ht);
}

/*
 * Called from signal handler.
 */
void lttng_consumer_should_exit(struct lttng_consumer_local_data *ctx)
{
	int ret;
	consumer_quit = 1;
	do {
		ret = write(ctx->consumer_should_quit[1], "4", 1);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("write consumer quit");
	}
}

void lttng_consumer_sync_trace_file(struct lttng_consumer_stream *stream,
		off_t orig_offset)
{
	int outfd = stream->out_fd;

	/*
	 * This does a blocking write-and-wait on any page that belongs to the
	 * subbuffer prior to the one we just wrote.
	 * Don't care about error values, as these are just hints and ways to
	 * limit the amount of page cache used.
	 */
	if (orig_offset < stream->chan->max_sb_size) {
		return;
	}
	lttng_sync_file_range(outfd, orig_offset - stream->chan->max_sb_size,
			stream->chan->max_sb_size,
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
	posix_fadvise(outfd, orig_offset - stream->chan->max_sb_size,
			stream->chan->max_sb_size, POSIX_FADV_DONTNEED);
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
		int (*update_stream)(int stream_key, uint32_t state))
{
	int ret, i;
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
	/* assign the callbacks */
	ctx->on_buffer_ready = buffer_ready;
	ctx->on_recv_channel = recv_channel;
	ctx->on_recv_stream = recv_stream;
	ctx->on_update_stream = update_stream;

	ret = pipe(ctx->consumer_poll_pipe);
	if (ret < 0) {
		PERROR("Error creating poll pipe");
		goto error_poll_pipe;
	}

	/* set read end of the pipe to non-blocking */
	ret = fcntl(ctx->consumer_poll_pipe[0], F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl O_NONBLOCK");
		goto error_poll_fcntl;
	}

	/* set write end of the pipe to non-blocking */
	ret = fcntl(ctx->consumer_poll_pipe[1], F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl O_NONBLOCK");
		goto error_poll_fcntl;
	}

	ret = pipe(ctx->consumer_should_quit);
	if (ret < 0) {
		PERROR("Error creating recv pipe");
		goto error_quit_pipe;
	}

	ret = pipe(ctx->consumer_thread_pipe);
	if (ret < 0) {
		PERROR("Error creating thread pipe");
		goto error_thread_pipe;
	}

	ret = utils_create_pipe(ctx->consumer_metadata_pipe);
	if (ret < 0) {
		goto error_metadata_pipe;
	}

	ret = utils_create_pipe(ctx->consumer_splice_metadata_pipe);
	if (ret < 0) {
		goto error_splice_pipe;
	}

	return ctx;

error_splice_pipe:
	utils_close_pipe(ctx->consumer_metadata_pipe);
error_metadata_pipe:
	utils_close_pipe(ctx->consumer_thread_pipe);
error_thread_pipe:
	for (i = 0; i < 2; i++) {
		int err;

		err = close(ctx->consumer_should_quit[i]);
		if (err) {
			PERROR("close");
		}
	}
error_poll_fcntl:
error_quit_pipe:
	for (i = 0; i < 2; i++) {
		int err;

		err = close(ctx->consumer_poll_pipe[i]);
		if (err) {
			PERROR("close");
		}
	}
error_poll_pipe:
	free(ctx);
error:
	return NULL;
}

/*
 * Close all fds associated with the instance and free the context.
 */
void lttng_consumer_destroy(struct lttng_consumer_local_data *ctx)
{
	int ret;

	ret = close(ctx->consumer_error_socket);
	if (ret) {
		PERROR("close");
	}
	ret = close(ctx->consumer_thread_pipe[0]);
	if (ret) {
		PERROR("close");
	}
	ret = close(ctx->consumer_thread_pipe[1]);
	if (ret) {
		PERROR("close");
	}
	ret = close(ctx->consumer_poll_pipe[0]);
	if (ret) {
		PERROR("close");
	}
	ret = close(ctx->consumer_poll_pipe[1]);
	if (ret) {
		PERROR("close");
	}
	ret = close(ctx->consumer_should_quit[0]);
	if (ret) {
		PERROR("close");
	}
	ret = close(ctx->consumer_should_quit[1]);
	if (ret) {
		PERROR("close");
	}
	utils_close_pipe(ctx->consumer_splice_metadata_pipe);

	unlink(ctx->consumer_command_sock_path);
	free(ctx);
}

/*
 * Write the metadata stream id on the specified file descriptor.
 */
static int write_relayd_metadata_id(int fd,
		struct lttng_consumer_stream *stream,
		struct consumer_relayd_sock_pair *relayd,
		unsigned long padding)
{
	int ret;
	struct lttcomm_relayd_metadata_payload hdr;

	hdr.stream_id = htobe64(stream->relayd_stream_id);
	hdr.padding_size = htobe32(padding);
	do {
		ret = write(fd, (void *) &hdr, sizeof(hdr));
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("write metadata stream id");
		goto end;
	}
	DBG("Metadata stream id %" PRIu64 " with padding %lu written before data",
			stream->relayd_stream_id, padding);

end:
	return ret;
}

/*
 * Mmap the ring buffer, read it and write the data to the tracefile. This is a
 * core function for writing trace buffers to either the local filesystem or
 * the network.
 *
 * Careful review MUST be put if any changes occur!
 *
 * Returns the number of bytes written
 */
ssize_t lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding)
{
	unsigned long mmap_offset;
	ssize_t ret = 0, written = 0;
	off_t orig_offset = stream->out_fd_offset;
	/* Default is on the disk */
	int outfd = stream->out_fd;
	struct consumer_relayd_sock_pair *relayd = NULL;

	/* RCU lock for the relayd pointer */
	rcu_read_lock();

	/* Flag that the current stream if set for network streaming. */
	if (stream->net_seq_idx != -1) {
		relayd = consumer_find_relayd(stream->net_seq_idx);
		if (relayd == NULL) {
			goto end;
		}
	}

	/* get the offset inside the fd to mmap */
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		ret = kernctl_get_mmap_read_offset(stream->wait_fd, &mmap_offset);
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		ret = lttng_ustctl_get_mmap_read_offset(stream->chan->handle,
				stream->buf, &mmap_offset);
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
	}
	if (ret != 0) {
		errno = -ret;
		PERROR("tracer ctl get_mmap_read_offset");
		written = ret;
		goto end;
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
			netlen += sizeof(struct lttcomm_relayd_metadata_payload);
		}

		ret = write_relayd_stream_header(stream, netlen, padding, relayd);
		if (ret >= 0) {
			/* Use the returned socket. */
			outfd = ret;

			/* Write metadata stream id before payload */
			if (stream->metadata_flag) {
				ret = write_relayd_metadata_id(outfd, stream, relayd, padding);
				if (ret < 0) {
					written = ret;
					goto end;
				}
			}
		}
		/* Else, use the default set before which is the filesystem. */
	} else {
		/* No streaming, we have to set the len with the full padding */
		len += padding;
	}

	while (len > 0) {
		do {
			ret = write(outfd, stream->mmap_base + mmap_offset, len);
		} while (ret < 0 && errno == EINTR);
		DBG("Consumer mmap write() ret %zd (len %lu)", ret, len);
		if (ret < 0) {
			PERROR("Error in file write");
			if (written == 0) {
				written = ret;
			}
			goto end;
		} else if (ret > len) {
			PERROR("Error in file write (ret %zd > len %lu)", ret, len);
			written += ret;
			goto end;
		} else {
			len -= ret;
			mmap_offset += ret;
		}

		/* This call is useless on a socket so better save a syscall. */
		if (!relayd) {
			/* This won't block, but will start writeout asynchronously */
			lttng_sync_file_range(outfd, stream->out_fd_offset, ret,
					SYNC_FILE_RANGE_WRITE);
			stream->out_fd_offset += ret;
		}
		written += ret;
	}
	lttng_consumer_sync_trace_file(stream, orig_offset);

end:
	/* Unlock only if ctrl socket used */
	if (relayd && stream->metadata_flag) {
		pthread_mutex_unlock(&relayd->ctrl_sock_mutex);
	}

	rcu_read_unlock();
	return written;
}

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * Returns the number of bytes spliced.
 */
ssize_t lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len,
		unsigned long padding)
{
	ssize_t ret = 0, written = 0, ret_splice = 0;
	loff_t offset = 0;
	off_t orig_offset = stream->out_fd_offset;
	int fd = stream->wait_fd;
	/* Default is on the disk */
	int outfd = stream->out_fd;
	struct consumer_relayd_sock_pair *relayd = NULL;
	int *splice_pipe;

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
	if (stream->net_seq_idx != -1) {
		relayd = consumer_find_relayd(stream->net_seq_idx);
		if (relayd == NULL) {
			goto end;
		}
	}

	/*
	 * Choose right pipe for splice. Metadata and trace data are handled by
	 * different threads hence the use of two pipes in order not to race or
	 * corrupt the written data.
	 */
	if (stream->metadata_flag) {
		splice_pipe = ctx->consumer_splice_metadata_pipe;
	} else {
		splice_pipe = ctx->consumer_thread_pipe;
	}

	/* Write metadata stream id before payload */
	if (relayd) {
		int total_len = len;

		if (stream->metadata_flag) {
			/*
			 * Lock the control socket for the complete duration of the function
			 * since from this point on we will use the socket.
			 */
			pthread_mutex_lock(&relayd->ctrl_sock_mutex);

			ret = write_relayd_metadata_id(splice_pipe[1], stream, relayd,
					padding);
			if (ret < 0) {
				written = ret;
				goto end;
			}

			total_len += sizeof(struct lttcomm_relayd_metadata_payload);
		}

		ret = write_relayd_stream_header(stream, total_len, padding, relayd);
		if (ret >= 0) {
			/* Use the returned socket. */
			outfd = ret;
		} else {
			ERR("Remote relayd disconnected. Stopping");
			goto end;
		}
	} else {
		/* No streaming, we have to set the len with the full padding */
		len += padding;
	}

	while (len > 0) {
		DBG("splice chan to pipe offset %lu of len %lu (fd : %d, pipe: %d)",
				(unsigned long)offset, len, fd, splice_pipe[1]);
		ret_splice = splice(fd, &offset, splice_pipe[1], NULL, len,
				SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("splice chan to pipe, ret %zd", ret_splice);
		if (ret_splice < 0) {
			PERROR("Error in relay splice");
			if (written == 0) {
				written = ret_splice;
			}
			ret = errno;
			goto splice_error;
		}

		/* Handle stream on the relayd if the output is on the network */
		if (relayd) {
			if (stream->metadata_flag) {
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
		}

		/* Splice data out */
		ret_splice = splice(splice_pipe[0], NULL, outfd, NULL,
				ret_splice, SPLICE_F_MOVE | SPLICE_F_MORE);
		DBG("Consumer splice pipe to file, ret %zd", ret_splice);
		if (ret_splice < 0) {
			PERROR("Error in file splice");
			if (written == 0) {
				written = ret_splice;
			}
			ret = errno;
			goto splice_error;
		} else if (ret_splice > len) {
			errno = EINVAL;
			PERROR("Wrote more data than requested %zd (len: %lu)",
					ret_splice, len);
			written += ret_splice;
			ret = errno;
			goto splice_error;
		}
		len -= ret_splice;

		/* This call is useless on a socket so better save a syscall. */
		if (!relayd) {
			/* This won't block, but will start writeout asynchronously */
			lttng_sync_file_range(outfd, stream->out_fd_offset, ret_splice,
					SYNC_FILE_RANGE_WRITE);
			stream->out_fd_offset += ret_splice;
		}
		written += ret_splice;
	}
	lttng_consumer_sync_trace_file(stream, orig_offset);

	ret = ret_splice;

	goto end;

splice_error:
	/* send the appropriate error description to sessiond */
	switch (ret) {
	case EBADF:
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_SPLICE_EBADF);
		break;
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
int lttng_consumer_take_snapshot(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_take_snapshot(ctx, stream);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_take_snapshot(ctx, stream);
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
int lttng_consumer_get_produced_snapshot(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream,
		unsigned long *pos)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_get_produced_snapshot(ctx, stream, pos);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_get_produced_snapshot(ctx, stream, pos);
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

/*
 * Iterate over all streams of the hashtable and free them properly.
 *
 * XXX: Should not be only for metadata stream or else use an other name.
 */
static void destroy_stream_ht(struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	if (ht == NULL) {
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(ht->ht, &iter.iter, stream, waitfd_node.node) {
		ret = lttng_ht_del(ht, &iter);
		assert(!ret);

		call_rcu(&stream->waitfd_node.head, consumer_free_metadata_stream);
	}
	rcu_read_unlock();

	lttng_ht_destroy(ht);
}

/*
 * Clean up a metadata stream and free its memory.
 */
void consumer_del_metadata_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *free_chan = NULL;
	struct consumer_relayd_sock_pair *relayd;

	assert(stream);
	/*
	 * This call should NEVER receive regular stream. It must always be
	 * metadata stream and this is crucial for data structure synchronization.
	 */
	assert(stream->metadata_flag);

	DBG3("Consumer delete metadata stream %d", stream->wait_fd);

	if (ht == NULL) {
		/* Means the stream was allocated but not successfully added */
		goto free_stream;
	}

	pthread_mutex_lock(&consumer_data.lock);
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		if (stream->mmap_base != NULL) {
			ret = munmap(stream->mmap_base, stream->mmap_len);
			if (ret != 0) {
				PERROR("munmap metadata stream");
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
		goto end;
	}

	rcu_read_lock();
	iter.iter.node = &stream->waitfd_node.node;
	ret = lttng_ht_del(ht, &iter);
	assert(!ret);
	rcu_read_unlock();

	if (stream->out_fd >= 0) {
		ret = close(stream->out_fd);
		if (ret) {
			PERROR("close");
		}
	}

	if (stream->wait_fd >= 0 && !stream->wait_fd_is_copy) {
		ret = close(stream->wait_fd);
		if (ret) {
			PERROR("close");
		}
	}

	if (stream->shm_fd >= 0 && stream->wait_fd != stream->shm_fd) {
		ret = close(stream->shm_fd);
		if (ret) {
			PERROR("close");
		}
	}

	/* Check and cleanup relayd */
	rcu_read_lock();
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd != NULL) {
		uatomic_dec(&relayd->refcount);
		assert(uatomic_read(&relayd->refcount) >= 0);

		/* Closing streams requires to lock the control socket. */
		pthread_mutex_lock(&relayd->ctrl_sock_mutex);
		ret = relayd_send_close_stream(&relayd->control_sock,
				stream->relayd_stream_id, stream->next_net_seq_num - 1);
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
			destroy_relayd(relayd);
		}
	}
	rcu_read_unlock();

	/* Atomically decrement channel refcount since other threads can use it. */
	uatomic_dec(&stream->chan->refcount);
	if (!uatomic_read(&stream->chan->refcount)
			&& !uatomic_read(&stream->chan->nb_init_streams)) {
		/* Go for channel deletion! */
		free_chan = stream->chan;
	}

end:
	pthread_mutex_unlock(&consumer_data.lock);

	if (free_chan) {
		consumer_del_channel(free_chan);
	}

free_stream:
	call_rcu(&stream->waitfd_node.head, consumer_free_metadata_stream);
}

/*
 * Action done with the metadata stream when adding it to the consumer internal
 * data structures to handle it.
 */
static int consumer_add_metadata_stream(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht)
{
	int ret = 0;
	struct consumer_relayd_sock_pair *relayd;

	assert(stream);
	assert(ht);

	DBG3("Adding metadata stream %d to hash table", stream->wait_fd);

	pthread_mutex_lock(&consumer_data.lock);

	/*
	 * From here, refcounts are updated so be _careful_ when returning an error
	 * after this point.
	 */

	rcu_read_lock();
	/* Find relayd and, if one is found, increment refcount. */
	relayd = consumer_find_relayd(stream->net_seq_idx);
	if (relayd != NULL) {
		uatomic_inc(&relayd->refcount);
	}

	/* Update channel refcount once added without error(s). */
	uatomic_inc(&stream->chan->refcount);

	/*
	 * When nb_init_streams reaches 0, we don't need to trigger any action in
	 * terms of destroying the associated channel, because the action that
	 * causes the count to become 0 also causes a stream to be added. The
	 * channel deletion will thus be triggered by the following removal of this
	 * stream.
	 */
	if (uatomic_read(&stream->chan->nb_init_streams) > 0) {
		uatomic_dec(&stream->chan->nb_init_streams);
	}

	lttng_ht_add_unique_ulong(ht, &stream->waitfd_node);
	rcu_read_unlock();

	pthread_mutex_unlock(&consumer_data.lock);
	return ret;
}

/*
 * Thread polls on metadata file descriptor and write them on disk or on the
 * network.
 */
void *consumer_thread_metadata_poll(void *data)
{
	int ret, i, pollfd;
	uint32_t revents, nb_fd;
	struct lttng_consumer_stream *stream = NULL;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht *metadata_ht = NULL;
	struct lttng_poll_event events;
	struct lttng_consumer_local_data *ctx = data;
	ssize_t len;

	rcu_register_thread();

	DBG("Thread metadata poll started");

	metadata_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (metadata_ht == NULL) {
		goto end;
	}

	/* Size is set to 1 for the consumer_metadata pipe */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		ERR("Poll set creation failed");
		goto end;
	}

	ret = lttng_poll_add(&events, ctx->consumer_metadata_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto end;
	}

	/* Main loop */
	DBG("Metadata main loop started");

	while (1) {
		lttng_poll_reset(&events);

		nb_fd = LTTNG_POLL_GETNB(&events);

		/* Only the metadata pipe is set */
		if (nb_fd == 0 && consumer_quit == 1) {
			goto end;
		}

restart:
		DBG("Metadata poll wait with %d fd(s)", nb_fd);
		ret = lttng_poll_wait(&events, -1);
		DBG("Metadata event catched in thread");
		if (ret < 0) {
			if (errno == EINTR) {
				ERR("Poll EINTR catched");
				goto restart;
			}
			goto error;
		}

		/* From here, the event is a metadata wait fd */
		for (i = 0; i < nb_fd; i++) {
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Just don't waste time if no returned events for the fd */
			if (!revents) {
				continue;
			}

			if (pollfd == ctx->consumer_metadata_pipe[0]) {
				if (revents & (LPOLLERR | LPOLLHUP )) {
					DBG("Metadata thread pipe hung up");
					/*
					 * Remove the pipe from the poll set and continue the loop
					 * since their might be data to consume.
					 */
					lttng_poll_del(&events, ctx->consumer_metadata_pipe[0]);
					close(ctx->consumer_metadata_pipe[0]);
					continue;
				} else if (revents & LPOLLIN) {
					do {
						/* Get the stream pointer received */
						ret = read(pollfd, &stream, sizeof(stream));
					} while (ret < 0 && errno == EINTR);
					if (ret < 0 ||
							ret < sizeof(struct lttng_consumer_stream *)) {
						PERROR("read metadata stream");
						/*
						 * Let's continue here and hope we can still work
						 * without stopping the consumer. XXX: Should we?
						 */
						continue;
					}

					DBG("Adding metadata stream %d to poll set",
							stream->wait_fd);

					ret = consumer_add_metadata_stream(stream, metadata_ht);
					if (ret) {
						ERR("Unable to add metadata stream");
						/* Stream was not setup properly. Continuing. */
						consumer_del_metadata_stream(stream, NULL);
						continue;
					}

					/* Add metadata stream to the global poll events list */
					lttng_poll_add(&events, stream->wait_fd,
							LPOLLIN | LPOLLPRI);
				}

				/* Handle other stream */
				continue;
			}

			rcu_read_lock();
			lttng_ht_lookup(metadata_ht, (void *)((unsigned long) pollfd),
					&iter);
			node = lttng_ht_iter_get_node_ulong(&iter);
			assert(node);

			stream = caa_container_of(node, struct lttng_consumer_stream,
					waitfd_node);

			/* Check for error event */
			if (revents & (LPOLLERR | LPOLLHUP)) {
				DBG("Metadata fd %d is hup|err.", pollfd);
				if (!stream->hangup_flush_done
						&& (consumer_data.type == LTTNG_CONSUMER32_UST
							|| consumer_data.type == LTTNG_CONSUMER64_UST)) {
					DBG("Attempting to flush and consume the UST buffers");
					lttng_ustconsumer_on_stream_hangup(stream);

					/* We just flushed the stream now read it. */
					do {
						len = ctx->on_buffer_ready(stream, ctx);
						/*
						 * We don't check the return value here since if we get
						 * a negative len, it means an error occured thus we
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
			} else if (revents & (LPOLLIN | LPOLLPRI)) {
				/* Get the data out of the metadata file descriptor */
				DBG("Metadata available on fd %d", pollfd);
				assert(stream->wait_fd == pollfd);

				len = ctx->on_buffer_ready(stream, ctx);
				/* It's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					rcu_read_unlock();
					goto end;
				} else if (len > 0) {
					stream->data_read = 1;
				}
			}

			/* Release RCU lock for the stream looked up */
			rcu_read_unlock();
		}
	}

error:
end:
	DBG("Metadata poll thread exiting");
	lttng_poll_clean(&events);

	if (metadata_ht) {
		destroy_stream_ht(metadata_ht);
	}

	rcu_unregister_thread();
	return NULL;
}

/*
 * This thread polls the fds in the set to consume the data and write
 * it to tracefile if necessary.
 */
void *consumer_thread_data_poll(void *data)
{
	int num_rdy, num_hup, high_prio, ret, i;
	struct pollfd *pollfd = NULL;
	/* local view of the streams */
	struct lttng_consumer_stream **local_stream = NULL, *new_stream = NULL;
	/* local view of consumer_data.fds_count */
	int nb_fd = 0;
	struct lttng_consumer_local_data *ctx = data;
	ssize_t len;

	rcu_register_thread();

	local_stream = zmalloc(sizeof(struct lttng_consumer_stream));

	while (1) {
		high_prio = 0;
		num_hup = 0;

		/*
		 * the fds set has been updated, we need to update our
		 * local array as well
		 */
		pthread_mutex_lock(&consumer_data.lock);
		if (consumer_data.need_update) {
			if (pollfd != NULL) {
				free(pollfd);
				pollfd = NULL;
			}
			if (local_stream != NULL) {
				free(local_stream);
				local_stream = NULL;
			}

			/* allocate for all fds + 1 for the consumer_poll_pipe */
			pollfd = zmalloc((consumer_data.stream_count + 1) * sizeof(struct pollfd));
			if (pollfd == NULL) {
				PERROR("pollfd malloc");
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}

			/* allocate for all fds + 1 for the consumer_poll_pipe */
			local_stream = zmalloc((consumer_data.stream_count + 1) *
					sizeof(struct lttng_consumer_stream));
			if (local_stream == NULL) {
				PERROR("local_stream malloc");
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}
			ret = consumer_update_poll_array(ctx, &pollfd, local_stream);
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
		if (nb_fd == 0 && consumer_quit == 1) {
			goto end;
		}
		/* poll on the array of fds */
	restart:
		DBG("polling on %d fd", nb_fd + 1);
		num_rdy = poll(pollfd, nb_fd + 1, consumer_poll_timeout);
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

		/*
		 * If the consumer_poll_pipe triggered poll go directly to the
		 * beginning of the loop to update the array. We want to prioritize
		 * array update over low-priority reads.
		 */
		if (pollfd[nb_fd].revents & (POLLIN | POLLPRI)) {
			size_t pipe_readlen;

			DBG("consumer_poll_pipe wake up");
			/* Consume 1 byte of pipe data */
			do {
				pipe_readlen = read(ctx->consumer_poll_pipe[0], &new_stream,
						sizeof(new_stream));
			} while (pipe_readlen == -1 && errno == EINTR);

			/*
			 * If the stream is NULL, just ignore it. It's also possible that
			 * the sessiond poll thread changed the consumer_quit state and is
			 * waking us up to test it.
			 */
			if (new_stream == NULL) {
				continue;
			}

			ret = consumer_add_stream(new_stream);
			if (ret) {
				ERR("Consumer add stream %d failed. Continuing",
						new_stream->key);
				/*
				 * At this point, if the add_stream fails, it is not in the
				 * hash table thus passing the NULL value here.
				 */
				consumer_del_stream(new_stream, NULL);
			}

			/* Continue to update the local streams and handle prio ones */
			continue;
		}

		/* Take care of high priority channels first. */
		for (i = 0; i < nb_fd; i++) {
			if (pollfd[i].revents & POLLPRI) {
				DBG("Urgent read on fd %d", pollfd[i].fd);
				high_prio = 1;
				len = ctx->on_buffer_ready(local_stream[i], ctx);
				/* it's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					goto end;
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
			if ((pollfd[i].revents & POLLIN) ||
					local_stream[i]->hangup_flush_done) {
				DBG("Normal read on fd %d", pollfd[i].fd);
				len = ctx->on_buffer_ready(local_stream[i], ctx);
				/* it's ok to have an unavailable sub-buffer */
				if (len < 0 && len != -EAGAIN && len != -ENODATA) {
					goto end;
				} else if (len > 0) {
					local_stream[i]->data_read = 1;
				}
			}
		}

		/* Handle hangup and errors */
		for (i = 0; i < nb_fd; i++) {
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
					consumer_del_stream(local_stream[i],
							consumer_data.stream_ht);
					num_hup++;
				}
			} else if (pollfd[i].revents & POLLERR) {
				ERR("Error returned in polling fd %d.", pollfd[i].fd);
				if (!local_stream[i]->data_read) {
					consumer_del_stream(local_stream[i],
							consumer_data.stream_ht);
					num_hup++;
				}
			} else if (pollfd[i].revents & POLLNVAL) {
				ERR("Polling fd %d tells fd is not open.", pollfd[i].fd);
				if (!local_stream[i]->data_read) {
					consumer_del_stream(local_stream[i],
							consumer_data.stream_ht);
					num_hup++;
				}
			}
			local_stream[i]->data_read = 0;
		}
	}
end:
	DBG("polling thread exiting");
	if (pollfd != NULL) {
		free(pollfd);
		pollfd = NULL;
	}
	if (local_stream != NULL) {
		free(local_stream);
		local_stream = NULL;
	}

	/*
	 * Close the write side of the pipe so epoll_wait() in
	 * consumer_thread_metadata_poll can catch it. The thread is monitoring the
	 * read side of the pipe. If we close them both, epoll_wait strangely does
	 * not return and could create a endless wait period if the pipe is the
	 * only tracked fd in the poll set. The thread will take care of closing
	 * the read side.
	 */
	close(ctx->consumer_metadata_pipe[1]);

	rcu_unregister_thread();
	return NULL;
}

/*
 * This thread listens on the consumerd socket and receives the file
 * descriptors from the session daemon.
 */
void *consumer_thread_sessiond_poll(void *data)
{
	int sock, client_socket, ret;
	/*
	 * structure to poll for incoming data on communication socket avoids
	 * making blocking sockets.
	 */
	struct pollfd consumer_sockpoll[2];
	struct lttng_consumer_local_data *ctx = data;

	rcu_register_thread();

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

	ret = fcntl(client_socket, F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl O_NONBLOCK");
		goto end;
	}

	/* prepare the FDs to poll : to client socket and the should_quit pipe */
	consumer_sockpoll[0].fd = ctx->consumer_should_quit[0];
	consumer_sockpoll[0].events = POLLIN | POLLPRI;
	consumer_sockpoll[1].fd = client_socket;
	consumer_sockpoll[1].events = POLLIN | POLLPRI;

	if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
		goto end;
	}
	DBG("Connection on client_socket");

	/* Blocking call, waiting for transmission */
	sock = lttcomm_accept_unix_sock(client_socket);
	if (sock <= 0) {
		WARN("On accept");
		goto end;
	}
	ret = fcntl(sock, F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		PERROR("fcntl O_NONBLOCK");
		goto end;
	}

	/* update the polling structure to poll on the established socket */
	consumer_sockpoll[1].fd = sock;
	consumer_sockpoll[1].events = POLLIN | POLLPRI;

	while (1) {
		if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
			goto end;
		}
		DBG("Incoming command on sock");
		ret = lttng_consumer_recv_cmd(ctx, sock, consumer_sockpoll);
		if (ret == -ENOENT) {
			DBG("Received STOP command");
			goto end;
		}
		if (ret <= 0) {
			/*
			 * This could simply be a session daemon quitting. Don't output
			 * ERR() here.
			 */
			DBG("Communication interrupted on command socket");
			goto end;
		}
		if (consumer_quit) {
			DBG("consumer_thread_receive_fds received quit from signal");
			goto end;
		}
		DBG("received fds on sock");
	}
end:
	DBG("consumer_thread_receive_fds exiting");

	/*
	 * when all fds have hung up, the polling thread
	 * can exit cleanly
	 */
	consumer_quit = 1;

	/*
	 * 2s of grace period, if no polling events occur during
	 * this period, the polling thread will exit even if there
	 * are still open FDs (should not happen, but safety mechanism).
	 */
	consumer_poll_timeout = LTTNG_CONSUMER_POLL_TIMEOUT;

	/*
	 * Notify the data poll thread to poll back again and test the
	 * consumer_quit state to quit gracefully.
	 */
	do {
		struct lttng_consumer_stream *null_stream = NULL;

		ret = write(ctx->consumer_poll_pipe[1], &null_stream,
				sizeof(null_stream));
	} while (ret < 0 && errno == EINTR);

	rcu_unregister_thread();
	return NULL;
}

ssize_t lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_read_subbuffer(stream, ctx);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_read_subbuffer(stream, ctx);
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		return -ENOSYS;
	}
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
void lttng_consumer_init(void)
{
	consumer_data.stream_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	consumer_data.channel_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	consumer_data.relayd_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
}

/*
 * Process the ADD_RELAYD command receive by a consumer.
 *
 * This will create a relayd socket pair and add it to the relayd hash table.
 * The caller MUST acquire a RCU read side lock before calling it.
 */
int consumer_add_relayd_socket(int net_seq_idx, int sock_type,
		struct lttng_consumer_local_data *ctx, int sock,
		struct pollfd *consumer_sockpoll, struct lttcomm_sock *relayd_sock)
{
	int fd, ret = -1;
	struct consumer_relayd_sock_pair *relayd;

	DBG("Consumer adding relayd socket (idx: %d)", net_seq_idx);

	/* Get relayd reference if exists. */
	relayd = consumer_find_relayd(net_seq_idx);
	if (relayd == NULL) {
		/* Not found. Allocate one. */
		relayd = consumer_allocate_relayd_sock_pair(net_seq_idx);
		if (relayd == NULL) {
			lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_OUTFD_ERROR);
			goto error;
		}
	}

	/* Poll on consumer socket. */
	if (lttng_consumer_poll_socket(consumer_sockpoll) < 0) {
		ret = -EINTR;
		goto error;
	}

	/* Get relayd socket from session daemon */
	ret = lttcomm_recv_fds_unix_sock(sock, &fd, 1);
	if (ret != sizeof(fd)) {
		lttng_consumer_send_error(ctx, LTTCOMM_CONSUMERD_ERROR_RECV_FD);
		ret = -1;
		goto error;
	}

	/* Copy socket information and received FD */
	switch (sock_type) {
	case LTTNG_STREAM_CONTROL:
		/* Copy received lttcomm socket */
		lttcomm_copy_sock(&relayd->control_sock, relayd_sock);
		ret = lttcomm_create_sock(&relayd->control_sock);
		if (ret < 0) {
			goto error;
		}

		/* Close the created socket fd which is useless */
		close(relayd->control_sock.fd);

		/* Assign new file descriptor */
		relayd->control_sock.fd = fd;
		break;
	case LTTNG_STREAM_DATA:
		/* Copy received lttcomm socket */
		lttcomm_copy_sock(&relayd->data_sock, relayd_sock);
		ret = lttcomm_create_sock(&relayd->data_sock);
		if (ret < 0) {
			goto error;
		}

		/* Close the created socket fd which is useless */
		close(relayd->data_sock.fd);

		/* Assign new file descriptor */
		relayd->data_sock.fd = fd;
		break;
	default:
		ERR("Unknown relayd socket type (%d)", sock_type);
		goto error;
	}

	DBG("Consumer %s socket created successfully with net idx %d (fd: %d)",
			sock_type == LTTNG_STREAM_CONTROL ? "control" : "data",
			relayd->net_seq_idx, fd);

	/*
	 * Add relayd socket pair to consumer data hashtable. If object already
	 * exists or on error, the function gracefully returns.
	 */
	add_relayd(relayd);

	/* All good! */
	ret = 0;

error:
	return ret;
}
