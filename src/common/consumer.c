/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/kernel-consumer/kernel-consumer.h>
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
static struct lttng_consumer_stream *consumer_find_stream(int key)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct lttng_consumer_stream *stream = NULL;

	/* Negative keys are lookup failures */
	if (key < 0)
		return NULL;

	rcu_read_lock();

	lttng_ht_lookup(consumer_data.stream_ht, (void *)((unsigned long) key),
			&iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node != NULL) {
		stream = caa_container_of(node, struct lttng_consumer_stream, node);
	}

	rcu_read_unlock();

	return stream;
}

static void consumer_steal_stream_key(int key)
{
	struct lttng_consumer_stream *stream;

	stream = consumer_find_stream(key);
	if (stream)
		stream->key = -1;
}

static struct lttng_consumer_channel *consumer_find_channel(int key)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct lttng_consumer_channel *channel = NULL;

	/* Negative keys are lookup failures */
	if (key < 0)
		return NULL;

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

	channel = consumer_find_channel(key);
	if (channel)
		channel->key = -1;
}

/*
 * Remove a stream from the global list protected by a mutex. This
 * function is also responsible for freeing its data structures.
 */
void consumer_del_stream(struct lttng_consumer_stream *stream)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_consumer_channel *free_chan = NULL;

	pthread_mutex_lock(&consumer_data.lock);

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		if (stream->mmap_base != NULL) {
			ret = munmap(stream->mmap_base, stream->mmap_len);
			if (ret != 0) {
				perror("munmap");
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

	/* Get stream node from hash table */
	lttng_ht_lookup(consumer_data.stream_ht,
			(void *)((unsigned long) stream->key), &iter);
	/* Remove stream node from hash table */
	ret = lttng_ht_del(consumer_data.stream_ht, &iter);
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
		close(stream->out_fd);
	}
	if (stream->wait_fd >= 0 && !stream->wait_fd_is_copy) {
		close(stream->wait_fd);
	}
	if (stream->shm_fd >= 0 && stream->wait_fd != stream->shm_fd) {
		close(stream->shm_fd);
	}
	if (!--stream->chan->refcount)
		free_chan = stream->chan;
	free(stream);
end:
	consumer_data.need_update = 1;
	pthread_mutex_unlock(&consumer_data.lock);

	if (free_chan)
		consumer_del_channel(free_chan);
}

static void consumer_del_stream_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct lttng_consumer_stream *stream =
		caa_container_of(node, struct lttng_consumer_stream, node);

	consumer_del_stream(stream);
}

struct lttng_consumer_stream *consumer_allocate_stream(
		int channel_key, int stream_key,
		int shm_fd, int wait_fd,
		enum lttng_consumer_stream_state state,
		uint64_t mmap_len,
		enum lttng_event_output output,
		const char *path_name,
		uid_t uid,
		gid_t gid)
{
	struct lttng_consumer_stream *stream;
	int ret;

	stream = zmalloc(sizeof(*stream));
	if (stream == NULL) {
		perror("malloc struct lttng_consumer_stream");
		goto end;
	}
	stream->chan = consumer_find_channel(channel_key);
	if (!stream->chan) {
		perror("Unable to find channel key");
		goto end;
	}
	stream->chan->refcount++;
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
	strncpy(stream->path_name, path_name, PATH_MAX - 1);
	stream->path_name[PATH_MAX - 1] = '\0';
	lttng_ht_node_init_ulong(&stream->node, stream->key);

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		stream->cpu = stream->chan->cpucount++;
		ret = lttng_ustconsumer_allocate_stream(stream);
		if (ret) {
			free(stream);
			return NULL;
		}
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		goto end;
	}
	DBG("Allocated stream %s (key %d, shm_fd %d, wait_fd %d, mmap_len %llu, out_fd %d)",
			stream->path_name, stream->key,
			stream->shm_fd,
			stream->wait_fd,
			(unsigned long long) stream->mmap_len,
			stream->out_fd);
end:
	return stream;
}

/*
 * Add a stream to the global list protected by a mutex.
 */
int consumer_add_stream(struct lttng_consumer_stream *stream)
{
	int ret = 0;

	pthread_mutex_lock(&consumer_data.lock);
	/* Steal stream identifier, for UST */
	consumer_steal_stream_key(stream->key);
	rcu_read_lock();
	lttng_ht_add_unique_ulong(consumer_data.stream_ht, &stream->node);
	rcu_read_unlock();
	consumer_data.stream_count++;
	consumer_data.need_update = 1;

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		/* Streams are in CPU number order (we rely on this) */
		stream->cpu = stream->chan->nr_streams++;
		break;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		goto end;
	}

end:
	pthread_mutex_unlock(&consumer_data.lock);
	return ret;
}

/*
 * Update a stream according to what we just received.
 */
void consumer_change_stream_state(int stream_key,
		enum lttng_consumer_stream_state state)
{
	struct lttng_consumer_stream *stream;

	pthread_mutex_lock(&consumer_data.lock);
	stream = consumer_find_stream(stream_key);
	if (stream) {
		stream->state = state;
	}
	consumer_data.need_update = 1;
	pthread_mutex_unlock(&consumer_data.lock);
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

	lttng_ht_lookup(consumer_data.channel_ht,
			(void *)((unsigned long) channel->key), &iter);
	ret = lttng_ht_del(consumer_data.channel_ht, &iter);
	assert(!ret);

	rcu_read_unlock();

	if (channel->mmap_base != NULL) {
		ret = munmap(channel->mmap_base, channel->mmap_len);
		if (ret != 0) {
			perror("munmap");
		}
	}
	if (channel->wait_fd >= 0 && !channel->wait_fd_is_copy) {
		close(channel->wait_fd);
	}
	if (channel->shm_fd >= 0 && channel->wait_fd != channel->shm_fd) {
		close(channel->shm_fd);
	}
	free(channel);
end:
	pthread_mutex_unlock(&consumer_data.lock);
}

static void consumer_del_channel_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct lttng_consumer_channel *channel=
		caa_container_of(node, struct lttng_consumer_channel, node);

	consumer_del_channel(channel);
}

struct lttng_consumer_channel *consumer_allocate_channel(
		int channel_key,
		int shm_fd, int wait_fd,
		uint64_t mmap_len,
		uint64_t max_sb_size)
{
	struct lttng_consumer_channel *channel;
	int ret;

	channel = zmalloc(sizeof(*channel));
	if (channel == NULL) {
		perror("malloc struct lttng_consumer_channel");
		goto end;
	}
	channel->key = channel_key;
	channel->shm_fd = shm_fd;
	channel->wait_fd = wait_fd;
	channel->mmap_len = mmap_len;
	channel->max_sb_size = max_sb_size;
	channel->refcount = 0;
	channel->nr_streams = 0;
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
			channel->key,
			channel->shm_fd,
			channel->wait_fd,
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
	pthread_mutex_lock(&consumer_data.lock);
	/* Steal channel identifier, for UST */
	consumer_steal_channel_key(channel->key);
	rcu_read_lock();
	lttng_ht_add_unique_ulong(consumer_data.channel_ht, &channel->node);
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

	/*
	 * Insert the consumer_poll_pipe at the end of the array and don't
	 * increment i so nb_fd is the number of real FD.
	 */
	(*pollfd)[i].fd = ctx->consumer_poll_pipe[0];
	(*pollfd)[i].events = POLLIN;
	return i;
}

/*
 * Poll on the should_quit pipe and the command socket return -1 on error and
 * should exit, 0 if data is available on the command socket
 */
int lttng_consumer_poll_socket(struct pollfd *consumer_sockpoll)
{
	int num_rdy;

	num_rdy = poll(consumer_sockpoll, 2, -1);
	if (num_rdy == -1) {
		perror("Poll error");
		goto exit;
	}
	if (consumer_sockpoll[0].revents == POLLIN) {
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
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;

	rcu_read_lock();

	/*
	 * close all outfd. Called when there are no more threads running (after
	 * joining on the threads), no need to protect list iteration with mutex.
	 */
	cds_lfht_for_each_entry(consumer_data.stream_ht->ht, &iter.iter, node,
			node) {
		ret = lttng_ht_del(consumer_data.stream_ht, &iter);
		assert(!ret);
		call_rcu(&node->head, consumer_del_stream_rcu);
	}

	cds_lfht_for_each_entry(consumer_data.channel_ht->ht, &iter.iter, node,
			node) {
		ret = lttng_ht_del(consumer_data.channel_ht, &iter);
		assert(!ret);
		call_rcu(&node->head, consumer_del_channel_rcu);
	}

	rcu_read_unlock();
}

/*
 * Called from signal handler.
 */
void lttng_consumer_should_exit(struct lttng_consumer_local_data *ctx)
{
	int ret;
	consumer_quit = 1;
	ret = write(ctx->consumer_should_quit[1], "4", 1);
	if (ret < 0) {
		perror("write consumer quit");
	}
}

void lttng_consumer_sync_trace_file(
		struct lttng_consumer_stream *stream, off_t orig_offset)
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
	sync_file_range(outfd, orig_offset - stream->chan->max_sb_size,
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
		int (*buffer_ready)(struct lttng_consumer_stream *stream,
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
		perror("allocating context");
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
		perror("Error creating poll pipe");
		goto error_poll_pipe;
	}

	ret = pipe(ctx->consumer_should_quit);
	if (ret < 0) {
		perror("Error creating recv pipe");
		goto error_quit_pipe;
	}

	ret = pipe(ctx->consumer_thread_pipe);
	if (ret < 0) {
		perror("Error creating thread pipe");
		goto error_thread_pipe;
	}

	return ctx;


error_thread_pipe:
	for (i = 0; i < 2; i++) {
		int err;

		err = close(ctx->consumer_should_quit[i]);
		assert(!err);
	}
error_quit_pipe:
	for (i = 0; i < 2; i++) {
		int err;

		err = close(ctx->consumer_poll_pipe[i]);
		assert(!err);
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
	close(ctx->consumer_error_socket);
	close(ctx->consumer_thread_pipe[0]);
	close(ctx->consumer_thread_pipe[1]);
	close(ctx->consumer_poll_pipe[0]);
	close(ctx->consumer_poll_pipe[1]);
	close(ctx->consumer_should_quit[0]);
	close(ctx->consumer_should_quit[1]);
	unlink(ctx->consumer_command_sock_path);
	free(ctx);
}

/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written
 */
int lttng_consumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_on_read_subbuffer_mmap(ctx, stream, len);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return lttng_ustconsumer_on_read_subbuffer_mmap(ctx, stream, len);
	default:
		ERR("Unknown consumer_data type");
		assert(0);
	}
}

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * Returns the number of bytes spliced.
 */
int lttng_consumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len)
{
	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		return lttng_kconsumer_on_read_subbuffer_splice(ctx, stream, len);
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return -ENOSYS;
	default:
		ERR("Unknown consumer_data type");
		assert(0);
		return -ENOSYS;
	}

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
 * This thread polls the fds in the set to consume the data and write
 * it to tracefile if necessary.
 */
void *lttng_consumer_thread_poll_fds(void *data)
{
	int num_rdy, num_hup, high_prio, ret, i;
	struct pollfd *pollfd = NULL;
	/* local view of the streams */
	struct lttng_consumer_stream **local_stream = NULL;
	/* local view of consumer_data.fds_count */
	int nb_fd = 0;
	char tmp;
	int tmp2;
	struct lttng_consumer_local_data *ctx = data;

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
				perror("pollfd malloc");
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}

			/* allocate for all fds + 1 for the consumer_poll_pipe */
			local_stream = zmalloc((consumer_data.stream_count + 1) *
					sizeof(struct lttng_consumer_stream));
			if (local_stream == NULL) {
				perror("local_stream malloc");
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}
			ret = consumer_update_poll_array(ctx, &pollfd, local_stream);
			if (ret < 0) {
				ERR("Error in allocating pollfd or local_outfds");
				lttng_consumer_send_error(ctx, CONSUMERD_POLL_ERROR);
				pthread_mutex_unlock(&consumer_data.lock);
				goto end;
			}
			nb_fd = ret;
			consumer_data.need_update = 0;
		}
		pthread_mutex_unlock(&consumer_data.lock);

		/* poll on the array of fds */
		DBG("polling on %d fd", nb_fd + 1);
		num_rdy = poll(pollfd, nb_fd + 1, consumer_poll_timeout);
		DBG("poll num_rdy : %d", num_rdy);
		if (num_rdy == -1) {
			perror("Poll error");
			lttng_consumer_send_error(ctx, CONSUMERD_POLL_ERROR);
			goto end;
		} else if (num_rdy == 0) {
			DBG("Polling thread timed out");
			goto end;
		}

		/* No FDs and consumer_quit, consumer_cleanup the thread */
		if (nb_fd == 0 && consumer_quit == 1) {
			goto end;
		}

		/*
		 * If the consumer_poll_pipe triggered poll go
		 * directly to the beginning of the loop to update the
		 * array. We want to prioritize array update over
		 * low-priority reads.
		 */
		if (pollfd[nb_fd].revents & POLLIN) {
			DBG("consumer_poll_pipe wake up");
			tmp2 = read(ctx->consumer_poll_pipe[0], &tmp, 1);
			if (tmp2 < 0) {
				perror("read consumer poll");
			}
			continue;
		}

		/* Take care of high priority channels first. */
		for (i = 0; i < nb_fd; i++) {
			if (pollfd[i].revents & POLLPRI) {
				DBG("Urgent read on fd %d", pollfd[i].fd);
				high_prio = 1;
				ret = ctx->on_buffer_ready(local_stream[i], ctx);
				/* it's ok to have an unavailable sub-buffer */
				if (ret == EAGAIN) {
					ret = 0;
				}
			} else if (pollfd[i].revents & POLLERR) {
				ERR("Error returned in polling fd %d.", pollfd[i].fd);
				rcu_read_lock();
				consumer_del_stream_rcu(&local_stream[i]->node.head);
				rcu_read_unlock();
				num_hup++;
			} else if (pollfd[i].revents & POLLNVAL) {
				ERR("Polling fd %d tells fd is not open.", pollfd[i].fd);
				rcu_read_lock();
				consumer_del_stream_rcu(&local_stream[i]->node.head);
				rcu_read_unlock();
				num_hup++;
			} else if ((pollfd[i].revents & POLLHUP) &&
					!(pollfd[i].revents & POLLIN)) {
				if (consumer_data.type == LTTNG_CONSUMER32_UST
						|| consumer_data.type == LTTNG_CONSUMER64_UST) {
					DBG("Polling fd %d tells it has hung up. Attempting flush and read.",
						pollfd[i].fd);
					if (!local_stream[i]->hangup_flush_done) {
						lttng_ustconsumer_on_stream_hangup(local_stream[i]);
						/* read after flush */
						do {
							ret = ctx->on_buffer_ready(local_stream[i], ctx);
						} while (ret == EAGAIN);
					}
				} else {
					DBG("Polling fd %d tells it has hung up.", pollfd[i].fd);
				}
				rcu_read_lock();
				consumer_del_stream_rcu(&local_stream[i]->node.head);
				rcu_read_unlock();
				num_hup++;
			}
		}

		/* If every buffer FD has hung up, we end the read loop here */
		if (nb_fd > 0 && num_hup == nb_fd) {
			DBG("every buffer FD has hung up\n");
			if (consumer_quit == 1) {
				goto end;
			}
			continue;
		}

		/* Take care of low priority channels. */
		if (high_prio == 0) {
			for (i = 0; i < nb_fd; i++) {
				if (pollfd[i].revents & POLLIN) {
					DBG("Normal read on fd %d", pollfd[i].fd);
					ret = ctx->on_buffer_ready(local_stream[i], ctx);
					/* it's ok to have an unavailable subbuffer */
					if (ret == EAGAIN) {
						ret = 0;
					}
				}
			}
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
	rcu_unregister_thread();
	return NULL;
}

/*
 * This thread listens on the consumerd socket and receives the file
 * descriptors from the session daemon.
 */
void *lttng_consumer_thread_receive_fds(void *data)
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
	ret = lttng_consumer_send_error(ctx, CONSUMERD_COMMAND_SOCK_READY);
	/* return < 0 on error, but == 0 is not fatal */
	if (ret < 0) {
		ERR("Error sending ready command to lttng-sessiond");
		goto end;
	}

	ret = fcntl(client_socket, F_SETFL, O_NONBLOCK);
	if (ret < 0) {
		perror("fcntl O_NONBLOCK");
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
		perror("fcntl O_NONBLOCK");
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
		if (ret < 0) {
			ERR("Communication interrupted on command socket");
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

	/* wake up the polling thread */
	ret = write(ctx->consumer_poll_pipe[1], "4", 1);
	if (ret < 0) {
		perror("poll pipe write");
	}
	rcu_unregister_thread();
	return NULL;
}

int lttng_consumer_read_subbuffer(struct lttng_consumer_stream *stream,
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
}

