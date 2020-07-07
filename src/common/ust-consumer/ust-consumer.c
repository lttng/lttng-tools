/*
 * Copyright (C) 2011 Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
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
#include <stdbool.h>
#include <stdint.h>

#include <bin/lttng-consumerd/health-consumerd.h>
#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/relayd/relayd.h>
#include <common/compat/fcntl.h>
#include <common/compat/endian.h>
#include <common/consumer/consumer-metadata-cache.h>
#include <common/consumer/consumer-stream.h>
#include <common/consumer/consumer-timer.h>
#include <common/utils.h>
#include <common/index/index.h>
#include <common/consumer/consumer.h>
#include <common/optional.h>

#include "ust-consumer.h"

#define INT_MAX_STR_LEN 12	/* includes \0 */

extern struct lttng_consumer_global_data consumer_data;
extern int consumer_poll_timeout;

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

		health_code_update();

		cds_list_del(&stream->send_node);
		ustctl_destroy_stream(stream->ustream);
		lttng_trace_chunk_put(stream->trace_chunk);
		free(stream);
	}

	/*
	 * If a channel is available meaning that was created before the streams
	 * were, delete it.
	 */
	if (channel->uchan) {
		lttng_ustconsumer_del_channel(channel);
		lttng_ustconsumer_free_channel(channel);
	}

	if (channel->trace_chunk) {
		lttng_trace_chunk_put(channel->trace_chunk);
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

	stream = consumer_stream_create(
			channel,
			channel->key,
			key,
			channel->name,
			channel->relayd_id,
			channel->session_id,
			channel->trace_chunk,
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

	consumer_stream_update_channel_attributes(stream, channel);

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
		consumer_add_metadata_stream(stream);
		stream_pipe = ctx->consumer_metadata_pipe;
	} else {
		consumer_add_data_stream(stream);
		stream_pipe = ctx->consumer_data_pipe;
	}

	/*
	 * From this point on, the stream's ownership has been moved away from
	 * the channel and it becomes globally visible. Hence, remove it from
	 * the local stream list to prevent the stream from being both local and
	 * global.
	 */
	stream->globally_visible = 1;
	cds_list_del(&stream->send_node);

	ret = lttng_pipe_write(stream_pipe, &stream, sizeof(stream));
	if (ret < 0) {
		ERR("Consumer write %s stream to pipe %d",
				stream->metadata_flag ? "metadata" : "data",
				lttng_pipe_get_writefd(stream_pipe));
		if (stream->metadata_flag) {
			consumer_del_stream_for_metadata(stream);
		} else {
			consumer_del_stream_for_data(stream);
		}
		goto error;
	}

error:
	return ret;
}

static
int get_stream_shm_path(char *stream_shm_path, const char *shm_path, int cpu)
{
	char cpu_nr[INT_MAX_STR_LEN];  /* int max len */
	int ret;

	strncpy(stream_shm_path, shm_path, PATH_MAX);
	stream_shm_path[PATH_MAX - 1] = '\0';
	ret = snprintf(cpu_nr, INT_MAX_STR_LEN, "%i", cpu);
	if (ret < 0) {
		PERROR("snprintf");
		goto end;
	}
	strncat(stream_shm_path, cpu_nr,
		PATH_MAX - strlen(stream_shm_path) - 1);
	ret = 0;
end:
	return ret;
}

/*
 * Create streams for the given channel using liblttng-ust-ctl.
 * The channel lock must be acquired by the caller.
 *
 * Return 0 on success else a negative value.
 */
static int create_ust_streams(struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx)
{
	int ret, cpu = 0;
	struct ustctl_consumer_stream *ustream;
	struct lttng_consumer_stream *stream;
	pthread_mutex_t *current_stream_lock = NULL;

	assert(channel);
	assert(ctx);

	/*
	 * While a stream is available from ustctl. When NULL is returned, we've
	 * reached the end of the possible stream for the channel.
	 */
	while ((ustream = ustctl_create_stream(channel->uchan, cpu))) {
		int wait_fd;
		int ust_metadata_pipe[2];

		health_code_update();

		if (channel->type == CONSUMER_CHANNEL_TYPE_METADATA && channel->monitor) {
			ret = utils_create_pipe_cloexec_nonblock(ust_metadata_pipe);
			if (ret < 0) {
				ERR("Create ust metadata poll pipe");
				goto error;
			}
			wait_fd = ust_metadata_pipe[0];
		} else {
			wait_fd = ustctl_stream_get_wait_fd(ustream);
		}

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

		pthread_mutex_lock(&stream->lock);
		current_stream_lock = &stream->lock;
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
			if (channel->monitor) {
				/* Set metadata poll pipe if we created one */
				memcpy(stream->ust_metadata_poll_pipe,
						ust_metadata_pipe,
						sizeof(ust_metadata_pipe));
			}
		}
		pthread_mutex_unlock(&stream->lock);
		current_stream_lock = NULL;
	}

	return 0;

error:
error_alloc:
	if (current_stream_lock) {
		pthread_mutex_unlock(current_stream_lock);
	}
	return ret;
}

/*
 * create_posix_shm is never called concurrently within a process.
 */
static
int create_posix_shm(void)
{
	char tmp_name[NAME_MAX];
	int shmfd, ret;

	ret = snprintf(tmp_name, NAME_MAX, "/ust-shm-consumer-%d", getpid());
	if (ret < 0) {
		PERROR("snprintf");
		return -1;
	}
	/*
	 * Allocate shm, and immediately unlink its shm oject, keeping
	 * only the file descriptor as a reference to the object.
	 * We specifically do _not_ use the / at the beginning of the
	 * pathname so that some OS implementations can keep it local to
	 * the process (POSIX leaves this implementation-defined).
	 */
	shmfd = shm_open(tmp_name, O_CREAT | O_EXCL | O_RDWR, 0700);
	if (shmfd < 0) {
		PERROR("shm_open");
		goto error_shm_open;
	}
	ret = shm_unlink(tmp_name);
	if (ret < 0 && errno != ENOENT) {
		PERROR("shm_unlink");
		goto error_shm_release;
	}
	return shmfd;

error_shm_release:
	ret = close(shmfd);
	if (ret) {
		PERROR("close");
	}
error_shm_open:
	return -1;
}

static int open_ust_stream_fd(struct lttng_consumer_channel *channel, int cpu,
		const struct lttng_credentials *session_credentials)
{
	char shm_path[PATH_MAX];
	int ret;

	if (!channel->shm_path[0]) {
		return create_posix_shm();
	}
	ret = get_stream_shm_path(shm_path, channel->shm_path, cpu);
	if (ret) {
		goto error_shm_path;
	}
	return run_as_open(shm_path,
		O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR,
		session_credentials->uid, session_credentials->gid);

error_shm_path:
	return -1;
}

/*
 * Create an UST channel with the given attributes and send it to the session
 * daemon using the ust ctl API.
 *
 * Return 0 on success or else a negative value.
 */
static int create_ust_channel(struct lttng_consumer_channel *channel,
		struct ustctl_consumer_channel_attr *attr,
		struct ustctl_consumer_channel **ust_chanp)
{
	int ret, nr_stream_fds, i, j;
	int *stream_fds;
	struct ustctl_consumer_channel *ust_channel;

	assert(channel);
	assert(attr);
	assert(ust_chanp);
	assert(channel->buffer_credentials.is_set);

	DBG3("Creating channel to ustctl with attr: [overwrite: %d, "
			"subbuf_size: %" PRIu64 ", num_subbuf: %" PRIu64 ", "
			"switch_timer_interval: %u, read_timer_interval: %u, "
			"output: %d, type: %d", attr->overwrite, attr->subbuf_size,
			attr->num_subbuf, attr->switch_timer_interval,
			attr->read_timer_interval, attr->output, attr->type);

	if (channel->type == CONSUMER_CHANNEL_TYPE_METADATA)
		nr_stream_fds = 1;
	else
		nr_stream_fds = ustctl_get_nr_stream_per_channel();
	stream_fds = zmalloc(nr_stream_fds * sizeof(*stream_fds));
	if (!stream_fds) {
		ret = -1;
		goto error_alloc;
	}
	for (i = 0; i < nr_stream_fds; i++) {
		stream_fds[i] = open_ust_stream_fd(channel, i,
				&channel->buffer_credentials.value);
		if (stream_fds[i] < 0) {
			ret = -1;
			goto error_open;
		}
	}
	ust_channel = ustctl_create_channel(attr, stream_fds, nr_stream_fds);
	if (!ust_channel) {
		ret = -1;
		goto error_create;
	}
	channel->nr_stream_fds = nr_stream_fds;
	channel->stream_fds = stream_fds;
	*ust_chanp = ust_channel;

	return 0;

error_create:
error_open:
	for (j = i - 1; j >= 0; j--) {
		int closeret;

		closeret = close(stream_fds[j]);
		if (closeret) {
			PERROR("close");
		}
		if (channel->shm_path[0]) {
			char shm_path[PATH_MAX];

			closeret = get_stream_shm_path(shm_path,
					channel->shm_path, j);
			if (closeret) {
				ERR("Cannot get stream shm path");
			}
			closeret = run_as_unlink(shm_path,
					channel->buffer_credentials.value.uid,
					channel->buffer_credentials.value.gid);
			if (closeret) {
				PERROR("unlink %s", shm_path);
			}
		}
	}
	/* Try to rmdir all directories under shm_path root. */
	if (channel->root_shm_path[0]) {
		(void) run_as_rmdir_recursive(channel->root_shm_path,
				channel->buffer_credentials.value.uid,
				channel->buffer_credentials.value.gid,
				LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	}
	free(stream_fds);
error_alloc:
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
 * Send channel to sessiond and relayd if applicable.
 *
 * Return 0 on success or else a negative value.
 */
static int send_channel_to_sessiond_and_relayd(int sock,
		struct lttng_consumer_channel *channel,
		struct lttng_consumer_local_data *ctx, int *relayd_error)
{
	int ret, ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct lttng_consumer_stream *stream;
	uint64_t net_seq_idx = -1ULL;

	assert(channel);
	assert(ctx);
	assert(sock >= 0);

	DBG("UST consumer sending channel %s to sessiond", channel->name);

	if (channel->relayd_id != (uint64_t) -1ULL) {
		cds_list_for_each_entry(stream, &channel->streams.head, send_node) {

			health_code_update();

			/* Try to send the stream to the relayd if one is available. */
			DBG("Sending stream %" PRIu64 " of channel \"%s\" to relayd",
					stream->key, channel->name);
			ret = consumer_send_relayd_stream(stream, stream->chan->pathname);
			if (ret < 0) {
				/*
				 * Flag that the relayd was the problem here probably due to a
				 * communicaton error on the socket.
				 */
				if (relayd_error) {
					*relayd_error = 1;
				}
				ret_code = LTTCOMM_CONSUMERD_RELAYD_FAIL;
			}
			if (net_seq_idx == -1ULL) {
				net_seq_idx = stream->net_seq_idx;
			}
		}
	}

	/* Inform sessiond that we are about to send channel and streams. */
	ret = consumer_send_status_msg(sock, ret_code);
	if (ret < 0 || ret_code != LTTCOMM_CONSUMERD_SUCCESS) {
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

		health_code_update();

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
	if (ret_code != LTTCOMM_CONSUMERD_SUCCESS) {
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
static int ask_channel(struct lttng_consumer_local_data *ctx,
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
	ret = create_ust_channel(channel, attr, &channel->uchan);
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
	pthread_mutex_lock(&channel->lock);
	ret = create_ust_streams(channel, ctx);
	pthread_mutex_unlock(&channel->lock);
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

		health_code_update();

		/* Sending the stream to the thread. */
		ret = send_stream_to_thread(stream, ctx);
		if (ret < 0) {
			/*
			 * If we are unable to send the stream to the thread, there is
			 * a big problem so just stop everything.
			 */
			goto error;
		}
	}

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

		health_code_update();

		pthread_mutex_lock(&stream->lock);

		/*
		 * Protect against concurrent teardown of a stream.
		 */
		if (cds_lfht_is_node_deleted(&stream->node.node)) {
			goto next;
		}

		if (!stream->quiescent) {
			ustctl_flush_buffer(stream->ustream, 0);
			stream->quiescent = true;
		}
next:
		pthread_mutex_unlock(&stream->lock);
	}
error:
	rcu_read_unlock();
	return ret;
}

/*
 * Clear quiescent state from channel's streams using the given key to
 * retrieve the channel.
 *
 * Return 0 on success else an LTTng error code.
 */
static int clear_quiescent_channel(uint64_t chan_key)
{
	int ret = 0;
	struct lttng_consumer_channel *channel;
	struct lttng_consumer_stream *stream;
	struct lttng_ht *ht;
	struct lttng_ht_iter iter;

	DBG("UST consumer clear quiescent channel key %" PRIu64, chan_key);

	rcu_read_lock();
	channel = consumer_find_channel(chan_key);
	if (!channel) {
		ERR("UST consumer clear quiescent channel %" PRIu64 " not found", chan_key);
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto error;
	}

	ht = consumer_data.stream_per_chan_id_ht;

	/* For each stream of the channel id, clear quiescent state. */
	cds_lfht_for_each_entry_duplicate(ht->ht,
			ht->hash_fct(&channel->key, lttng_ht_seed), ht->match_fct,
			&channel->key, &iter.iter, stream, node_channel_id.node) {

		health_code_update();

		pthread_mutex_lock(&stream->lock);
		stream->quiescent = false;
		pthread_mutex_unlock(&stream->lock);
	}
error:
	rcu_read_unlock();
	return ret;
}

/*
 * Close metadata stream wakeup_fd using the given key to retrieve the channel.
 *
 * Return 0 on success else an LTTng error code.
 */
static int close_metadata(uint64_t chan_key)
{
	int ret = 0;
	struct lttng_consumer_channel *channel;
	unsigned int channel_monitor;

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
	channel_monitor = channel->monitor;
	if (cds_lfht_is_node_deleted(&channel->node.node)) {
		goto error_unlock;
	}

	lttng_ustconsumer_close_metadata(channel);
	pthread_mutex_unlock(&channel->lock);
	pthread_mutex_unlock(&consumer_data.lock);

	/*
	 * The ownership of a metadata channel depends on the type of
	 * session to which it belongs. In effect, the monitor flag is checked
	 * to determine if this metadata channel is in "snapshot" mode or not.
	 *
	 * In the non-snapshot case, the metadata channel is created along with
	 * a single stream which will remain present until the metadata channel
	 * is destroyed (on the destruction of its session). In this case, the
	 * metadata stream in "monitored" by the metadata poll thread and holds
	 * the ownership of its channel.
	 *
	 * Closing the metadata will cause the metadata stream's "metadata poll
	 * pipe" to be closed. Closing this pipe will wake-up the metadata poll
	 * thread which will teardown the metadata stream which, in return,
	 * deletes the metadata channel.
	 *
	 * In the snapshot case, the metadata stream is created and destroyed
	 * on every snapshot record. Since the channel doesn't have an owner
	 * other than the session daemon, it is safe to destroy it immediately
	 * on reception of the CLOSE_METADATA command.
	 */
	if (!channel_monitor) {
		/*
		 * The channel and consumer_data locks must be
		 * released before this call since consumer_del_channel
		 * re-acquires the channel and consumer_data locks to teardown
		 * the channel and queue its reclamation by the "call_rcu"
		 * worker thread.
		 */
		consumer_del_channel(channel);
	}

	return ret;
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
		ret = consumer_send_relayd_streams_sent(
				metadata->metadata_stream->net_seq_idx);
		if (ret < 0) {
			ret = LTTCOMM_CONSUMERD_RELAYD_FAIL;
			goto error;
		}
	}

	/*
	 * Ownership of metadata stream is passed along. Freeing is handled by
	 * the callee.
	 */
	ret = send_streams_to_thread(metadata, ctx);
	if (ret < 0) {
		/*
		 * If we are unable to send the stream to the thread, there is
		 * a big problem so just stop everything.
		 */
		ret = LTTCOMM_CONSUMERD_FATAL;
		goto send_streams_error;
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
	consumer_stream_destroy(metadata->metadata_stream, NULL);
	cds_list_del(&metadata->metadata_stream->send_node);
	metadata->metadata_stream = NULL;
send_streams_error:
error_no_stream:
end:
	return ret;
}

/*
 * Snapshot the whole metadata.
 * RCU read-side lock must be held by the caller.
 *
 * Returns 0 on success, < 0 on error
 */
static int snapshot_metadata(struct lttng_consumer_channel *metadata_channel,
		uint64_t key, char *path, uint64_t relayd_id,
		struct lttng_consumer_local_data *ctx)
{
	int ret = 0;
	struct lttng_consumer_stream *metadata_stream;

	assert(path);
	assert(ctx);

	DBG("UST consumer snapshot metadata with key %" PRIu64 " at path %s",
			key, path);

	rcu_read_lock();

	assert(!metadata_channel->monitor);

	health_code_update();

	/*
	 * Ask the sessiond if we have new metadata waiting and update the
	 * consumer metadata cache.
	 */
	ret = lttng_ustconsumer_request_metadata(ctx, metadata_channel, 0, 1);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

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

	pthread_mutex_lock(&metadata_stream->lock);
	if (relayd_id != (uint64_t) -1ULL) {
		metadata_stream->net_seq_idx = relayd_id;
		ret = consumer_send_relayd_stream(metadata_stream, path);
	} else {
		ret = consumer_stream_create_output_files(metadata_stream,
				false);
	}
	pthread_mutex_unlock(&metadata_stream->lock);
	if (ret < 0) {
		goto error_stream;
	}

	do {
		health_code_update();

		ret = lttng_consumer_read_subbuffer(metadata_stream, ctx, true);
		if (ret < 0) {
			goto error_stream;
		}
	} while (ret > 0);

error_stream:
	/*
	 * Clean up the stream completly because the next snapshot will use a new
	 * metadata stream.
	 */
	consumer_stream_destroy(metadata_stream, NULL);
	cds_list_del(&metadata_stream->send_node);
	metadata_channel->metadata_stream = NULL;

error:
	rcu_read_unlock();
	return ret;
}

static
int get_current_subbuf_addr(struct lttng_consumer_stream *stream,
		const char **addr)
{
	int ret;
	unsigned long mmap_offset;
	const char *mmap_base;

	mmap_base = ustctl_get_mmap_base(stream->ustream);
	if (!mmap_base) {
		ERR("Failed to get mmap base for stream `%s`",
				stream->name);
		ret = -EPERM;
		goto error;
	}

	ret = ustctl_get_mmap_read_offset(stream->ustream, &mmap_offset);
	if (ret != 0) {
		ERR("Failed to get mmap offset for stream `%s`", stream->name);
		ret = -EINVAL;
		goto error;
	}

	*addr = mmap_base + mmap_offset;
error:
	return ret;

}

/*
 * Take a snapshot of all the stream of a channel.
 * RCU read-side lock and the channel lock must be held by the caller.
 *
 * Returns 0 on success, < 0 on error
 */
static int snapshot_channel(struct lttng_consumer_channel *channel,
		uint64_t key, char *path, uint64_t relayd_id,
		uint64_t nb_packets_per_stream,
		struct lttng_consumer_local_data *ctx)
{
	int ret;
	unsigned use_relayd = 0;
	unsigned long consumed_pos, produced_pos;
	struct lttng_consumer_stream *stream;

	assert(path);
	assert(ctx);

	rcu_read_lock();

	if (relayd_id != (uint64_t) -1ULL) {
		use_relayd = 1;
	}

	assert(!channel->monitor);
	DBG("UST consumer snapshot channel %" PRIu64, key);

	cds_list_for_each_entry(stream, &channel->streams.head, send_node) {
		health_code_update();

		/* Lock stream because we are about to change its state. */
		pthread_mutex_lock(&stream->lock);
		assert(channel->trace_chunk);
		if (!lttng_trace_chunk_get(channel->trace_chunk)) {
			/*
			 * Can't happen barring an internal error as the channel
			 * holds a reference to the trace chunk.
			 */
			ERR("Failed to acquire reference to channel's trace chunk");
			ret = -1;
			goto error_unlock;
		}
		assert(!stream->trace_chunk);
		stream->trace_chunk = channel->trace_chunk;

		stream->net_seq_idx = relayd_id;

		if (use_relayd) {
			ret = consumer_send_relayd_stream(stream, path);
			if (ret < 0) {
				goto error_unlock;
			}
		} else {
			ret = consumer_stream_create_output_files(stream,
					false);
			if (ret < 0) {
				goto error_unlock;
			}
			DBG("UST consumer snapshot stream (%" PRIu64 ")",
					stream->key);
		}

		/*
		 * If tracing is active, we want to perform a "full" buffer flush.
		 * Else, if quiescent, it has already been done by the prior stop.
		 */
		if (!stream->quiescent) {
			ustctl_flush_buffer(stream->ustream, 0);
		}

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
		 * the possible size of the snapshot. Also, we assume that the session
		 * daemon should never send a maximum stream size that is lower than
		 * subbuffer size.
		 */
		consumed_pos = consumer_get_consume_start_pos(consumed_pos,
				produced_pos, nb_packets_per_stream,
				stream->max_sb_size);

		while ((long) (consumed_pos - produced_pos) < 0) {
			ssize_t read_len;
			unsigned long len, padded_len;
			const char *subbuf_addr;
			struct lttng_buffer_view subbuf_view;

			health_code_update();

			DBG("UST consumer taking snapshot at pos %lu", consumed_pos);

			ret = ustctl_get_subbuf(stream->ustream, &consumed_pos);
			if (ret < 0) {
				if (ret != -EAGAIN) {
					PERROR("ustctl_get_subbuf snapshot");
					goto error_close_stream;
				}
				DBG("UST consumer get subbuf failed. Skipping it.");
				consumed_pos += stream->max_sb_size;
				stream->chan->lost_packets++;
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

			ret = get_current_subbuf_addr(stream, &subbuf_addr);
			if (ret) {
				goto error_put_subbuf;
			}

			subbuf_view = lttng_buffer_view_init(
					subbuf_addr, 0, padded_len);
			read_len = lttng_consumer_on_read_subbuffer_mmap(
					stream, &subbuf_view, padded_len - len);
			if (use_relayd) {
				if (read_len != len) {
					ret = -EPERM;
					goto error_put_subbuf;
				}
			} else {
				if (read_len != padded_len) {
					ret = -EPERM;
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
	rcu_read_unlock();
	return ret;
}

/*
 * Receive the metadata updates from the sessiond. Supports receiving
 * overlapping metadata, but is needs to always belong to a contiguous
 * range starting from 0.
 * Be careful about the locks held when calling this function: it needs
 * the metadata cache flush to concurrently progress in order to
 * complete.
 */
int lttng_ustconsumer_recv_metadata(int sock, uint64_t key, uint64_t offset,
		uint64_t len, uint64_t version,
		struct lttng_consumer_channel *channel, int timer, int wait)
{
	int ret, ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	char *metadata_str;

	DBG("UST consumer push metadata key %" PRIu64 " of len %" PRIu64, key, len);

	metadata_str = zmalloc(len * sizeof(char));
	if (!metadata_str) {
		PERROR("zmalloc metadata string");
		ret_code = LTTCOMM_CONSUMERD_ENOMEM;
		goto end;
	}

	health_code_update();

	/* Receive metadata string. */
	ret = lttcomm_recv_unix_sock(sock, metadata_str, len);
	if (ret < 0) {
		/* Session daemon is dead so return gracefully. */
		ret_code = ret;
		goto end_free;
	}

	health_code_update();

	pthread_mutex_lock(&channel->metadata_cache->lock);
	ret = consumer_metadata_cache_write(channel, offset, len, version,
			metadata_str);
	if (ret < 0) {
		/* Unable to handle metadata. Notify session daemon. */
		ret_code = LTTCOMM_CONSUMERD_ERROR_METADATA;
		/*
		 * Skip metadata flush on write error since the offset and len might
		 * not have been updated which could create an infinite loop below when
		 * waiting for the metadata cache to be flushed.
		 */
		pthread_mutex_unlock(&channel->metadata_cache->lock);
		goto end_free;
	}
	pthread_mutex_unlock(&channel->metadata_cache->lock);

	if (!wait) {
		goto end_free;
	}
	while (consumer_metadata_cache_flushed(channel, offset + len, timer)) {
		DBG("Waiting for metadata to be flushed");

		health_code_update();

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
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	struct lttcomm_consumer_msg msg;
	struct lttng_consumer_channel *channel = NULL;

	health_code_update();

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

	health_code_update();

	/* deprecated */
	assert(msg.cmd_type != LTTNG_CONSUMER_STOP);

	health_code_update();

	/* relayd needs RCU read-side lock */
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
	case LTTNG_CONSUMER_DESTROY_RELAYD:
	{
		uint64_t index = msg.u.destroy_relayd.net_seq_idx;
		struct consumer_relayd_sock_pair *relayd;

		DBG("UST consumer destroying relayd %" PRIu64, index);

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
		const uint64_t chunk_id = msg.u.ask_channel.chunk_id.value;
		const struct lttng_credentials buffer_credentials = {
			.uid = msg.u.ask_channel.buffer_credentials.uid,
			.gid = msg.u.ask_channel.buffer_credentials.gid,
		};

		/* Create a plain object and reserve a channel key. */
		channel = consumer_allocate_channel(
				msg.u.ask_channel.key,
				msg.u.ask_channel.session_id,
				msg.u.ask_channel.chunk_id.is_set ?
						&chunk_id : NULL,
				msg.u.ask_channel.pathname,
				msg.u.ask_channel.name,
				msg.u.ask_channel.relayd_id,
				(enum lttng_event_output) msg.u.ask_channel.output,
				msg.u.ask_channel.tracefile_size,
				msg.u.ask_channel.tracefile_count,
				msg.u.ask_channel.session_id_per_pid,
				msg.u.ask_channel.monitor,
				msg.u.ask_channel.live_timer_interval,
				msg.u.ask_channel.is_live,
				msg.u.ask_channel.root_shm_path,
				msg.u.ask_channel.shm_path);
		if (!channel) {
			goto end_channel_error;
		}

		LTTNG_OPTIONAL_SET(&channel->buffer_credentials,
				buffer_credentials);

		/*
		 * Assign UST application UID to the channel. This value is ignored for
		 * per PID buffers. This is specific to UST thus setting this after the
		 * allocation.
		 */
		channel->ust_app_uid = msg.u.ask_channel.ust_app_uid;

		/* Build channel attributes from received message. */
		attr.subbuf_size = msg.u.ask_channel.subbuf_size;
		attr.num_subbuf = msg.u.ask_channel.num_subbuf;
		attr.overwrite = msg.u.ask_channel.overwrite;
		attr.switch_timer_interval = msg.u.ask_channel.switch_timer_interval;
		attr.read_timer_interval = msg.u.ask_channel.read_timer_interval;
		attr.chan_id = msg.u.ask_channel.chan_id;
		memcpy(attr.uuid, msg.u.ask_channel.uuid, sizeof(attr.uuid));
		attr.blocking_timeout= msg.u.ask_channel.blocking_timeout;

		/* Match channel buffer type to the UST abi. */
		switch (msg.u.ask_channel.output) {
		case LTTNG_EVENT_MMAP:
		default:
			attr.output = LTTNG_UST_MMAP;
			break;
		}

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

		health_code_update();

		ret = ask_channel(ctx, channel, &attr);
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
		} else {
			int monitor_start_ret;

			consumer_timer_live_start(channel,
					msg.u.ask_channel.live_timer_interval);
			monitor_start_ret = consumer_timer_monitor_start(
					channel,
					msg.u.ask_channel.monitor_timer_interval);
			if (monitor_start_ret < 0) {
				ERR("Starting channel monitoring timer failed");
				goto end_channel_error;
			}
		}

		health_code_update();

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
			if (channel->live_timer_enabled == 1) {
				consumer_timer_live_stop(channel);
			}
			if (channel->monitor_timer_enabled == 1) {
				consumer_timer_monitor_stop(channel);
			}
			goto end_channel_error;
		}

		health_code_update();

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
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
			goto end_get_channel;
		}

		health_code_update();

		/* Send the channel to sessiond (and relayd, if applicable). */
		ret = send_channel_to_sessiond_and_relayd(sock, channel, ctx,
				&relayd_err);
		if (ret < 0) {
			if (relayd_err) {
				/*
				 * We were unable to send to the relayd the stream so avoid
				 * sending back a fatal error to the thread since this is OK
				 * and the consumer can continue its work. The above call
				 * has sent the error status message to the sessiond.
				 */
				goto end_get_channel_nosignal;
			}
			/*
			 * The communicaton was broken hence there is a bad state between
			 * the consumer and sessiond so stop everything.
			 */
			goto error_get_channel_fatal;
		}

		health_code_update();

		/*
		 * In no monitor mode, the streams ownership is kept inside the channel
		 * so don't send them to the data thread.
		 */
		if (!channel->monitor) {
			goto end_get_channel;
		}

		ret = send_streams_to_thread(channel, ctx);
		if (ret < 0) {
			/*
			 * If we are unable to send the stream to the thread, there is
			 * a big problem so just stop everything.
			 */
			goto error_get_channel_fatal;
		}
		/* List MUST be empty after or else it could be reused. */
		assert(cds_list_empty(&channel->streams.head));
end_get_channel:
		goto end_msg_sessiond;
error_get_channel_fatal:
		goto error_fatal;
end_get_channel_nosignal:
		goto end_nosignal;
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
	case LTTNG_CONSUMER_CLEAR_QUIESCENT_CHANNEL:
	{
		int ret;

		ret = clear_quiescent_channel(
				msg.u.clear_quiescent_channel.key);
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
		uint64_t version = msg.u.push_metadata.version;
		struct lttng_consumer_channel *channel;

		DBG("UST consumer push metadata key %" PRIu64 " of len %" PRIu64, key,
				len);

		channel = consumer_find_channel(key);
		if (!channel) {
			/*
			 * This is possible if the metadata creation on the consumer side
			 * is in flight vis-a-vis a concurrent push metadata from the
			 * session daemon.  Simply return that the channel failed and the
			 * session daemon will handle that message correctly considering
			 * that this race is acceptable thus the DBG() statement here.
			 */
			DBG("UST consumer push metadata %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHANNEL_FAIL;
			goto end_push_metadata_msg_sessiond;
		}

		health_code_update();

		if (!len) {
			/*
			 * There is nothing to receive. We have simply
			 * checked whether the channel can be found.
			 */
			ret_code = LTTCOMM_CONSUMERD_SUCCESS;
			goto end_push_metadata_msg_sessiond;
		}

		/* Tell session daemon we are ready to receive the metadata. */
		ret = consumer_send_status_msg(sock, LTTCOMM_CONSUMERD_SUCCESS);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto error_push_metadata_fatal;
		}

		health_code_update();

		/* Wait for more data. */
		health_poll_entry();
		ret = lttng_consumer_poll_socket(consumer_sockpoll);
		health_poll_exit();
		if (ret) {
			goto error_push_metadata_fatal;
		}

		health_code_update();

		ret = lttng_ustconsumer_recv_metadata(sock, key, offset,
				len, version, channel, 0, 1);
		if (ret < 0) {
			/* error receiving from sessiond */
			goto error_push_metadata_fatal;
		} else {
			ret_code = ret;
			goto end_push_metadata_msg_sessiond;
		}
end_push_metadata_msg_sessiond:
		goto end_msg_sessiond;
error_push_metadata_fatal:
		goto error_fatal;
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
		struct lttng_consumer_channel *channel;
		uint64_t key = msg.u.snapshot_channel.key;

		channel = consumer_find_channel(key);
		if (!channel) {
			DBG("UST snapshot channel not found for key %" PRIu64, key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		} else {
			if (msg.u.snapshot_channel.metadata) {
				ret = snapshot_metadata(channel, key,
						msg.u.snapshot_channel.pathname,
						msg.u.snapshot_channel.relayd_id,
						ctx);
				if (ret < 0) {
					ERR("Snapshot metadata failed");
					ret_code = LTTCOMM_CONSUMERD_SNAPSHOT_FAILED;
				}
			} else {
				ret = snapshot_channel(channel, key,
						msg.u.snapshot_channel.pathname,
						msg.u.snapshot_channel.relayd_id,
						msg.u.snapshot_channel.nb_packets_per_stream,
						ctx);
				if (ret < 0) {
					ERR("Snapshot channel failed");
					ret_code = LTTCOMM_CONSUMERD_SNAPSHOT_FAILED;
				}
			}
		}
		health_code_update();
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}
		health_code_update();
		break;
	}
	case LTTNG_CONSUMER_DISCARDED_EVENTS:
	{
		int ret = 0;
		uint64_t discarded_events;
		struct lttng_ht_iter iter;
		struct lttng_ht *ht;
		struct lttng_consumer_stream *stream;
		uint64_t id = msg.u.discarded_events.session_id;
		uint64_t key = msg.u.discarded_events.channel_key;

		DBG("UST consumer discarded events command for session id %"
				PRIu64, id);
		rcu_read_lock();
		pthread_mutex_lock(&consumer_data.lock);

		ht = consumer_data.stream_list_ht;

		/*
		 * We only need a reference to the channel, but they are not
		 * directly indexed, so we just use the first matching stream
		 * to extract the information we need, we default to 0 if not
		 * found (no events are dropped if the channel is not yet in
		 * use).
		 */
		discarded_events = 0;
		cds_lfht_for_each_entry_duplicate(ht->ht,
				ht->hash_fct(&id, lttng_ht_seed),
				ht->match_fct, &id,
				&iter.iter, stream, node_session_id.node) {
			if (stream->chan->key == key) {
				discarded_events = stream->chan->discarded_events;
				break;
			}
		}
		pthread_mutex_unlock(&consumer_data.lock);
		rcu_read_unlock();

		DBG("UST consumer discarded events command for session id %"
				PRIu64 ", channel key %" PRIu64, id, key);

		health_code_update();

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &discarded_events, sizeof(discarded_events));
		if (ret < 0) {
			PERROR("send discarded events");
			goto error_fatal;
		}

		break;
	}
	case LTTNG_CONSUMER_LOST_PACKETS:
	{
	        int ret;
		uint64_t lost_packets;
		struct lttng_ht_iter iter;
		struct lttng_ht *ht;
		struct lttng_consumer_stream *stream;
		uint64_t id = msg.u.lost_packets.session_id;
		uint64_t key = msg.u.lost_packets.channel_key;

		DBG("UST consumer lost packets command for session id %"
				PRIu64, id);
		rcu_read_lock();
		pthread_mutex_lock(&consumer_data.lock);

		ht = consumer_data.stream_list_ht;

		/*
		 * We only need a reference to the channel, but they are not
		 * directly indexed, so we just use the first matching stream
		 * to extract the information we need, we default to 0 if not
		 * found (no packets lost if the channel is not yet in use).
		 */
	        lost_packets = 0;
		cds_lfht_for_each_entry_duplicate(ht->ht,
				ht->hash_fct(&id, lttng_ht_seed),
				ht->match_fct, &id,
				&iter.iter, stream, node_session_id.node) {
			if (stream->chan->key == key) {
			        lost_packets = stream->chan->lost_packets;
				break;
			}
		}
		pthread_mutex_unlock(&consumer_data.lock);
		rcu_read_unlock();

		DBG("UST consumer lost packets command for session id %"
				PRIu64 ", channel key %" PRIu64, id, key);

		health_code_update();

		/* Send back returned value to session daemon */
		ret = lttcomm_send_unix_sock(sock, &lost_packets,
			        sizeof(lost_packets));
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
		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_ROTATE_CHANNEL:
	{
		struct lttng_consumer_channel *channel;
		uint64_t key = msg.u.rotate_channel.key;

		channel = consumer_find_channel(key);
		if (!channel) {
			DBG("Channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		} else {
			/*
			 * Sample the rotate position of all the streams in
			 * this channel.
			 */
			ret = lttng_consumer_rotate_channel(channel, key,
					msg.u.rotate_channel.relayd_id,
					msg.u.rotate_channel.metadata,
					ctx);
			if (ret < 0) {
				ERR("Rotate channel failed");
				ret_code = LTTCOMM_CONSUMERD_ROTATION_FAIL;
			}

			health_code_update();
		}
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_rotate_channel_nosignal;
		}

		/*
		 * Rotate the streams that are ready right now.
		 * FIXME: this is a second consecutive iteration over the
		 * streams in a channel, there is probably a better way to
		 * handle this, but it needs to be after the
		 * consumer_send_status_msg() call.
		 */
		if (channel) {
			ret = lttng_consumer_rotate_ready_streams(
					channel, key, ctx);
			if (ret < 0) {
				ERR("Rotate channel failed");
			}
		}
		break;
end_rotate_channel_nosignal:
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_CLEAR_CHANNEL:
	{
		struct lttng_consumer_channel *channel;
		uint64_t key = msg.u.clear_channel.key;

		channel = consumer_find_channel(key);
		if (!channel) {
			DBG("Channel %" PRIu64 " not found", key);
			ret_code = LTTCOMM_CONSUMERD_CHAN_NOT_FOUND;
		} else {
			ret = lttng_consumer_clear_channel(channel);
			if (ret) {
				ERR("Clear channel failed key %" PRIu64, key);
				ret_code = ret;
			}

			health_code_update();
		}
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}
		break;
	}
	case LTTNG_CONSUMER_INIT:
	{
		ret_code = lttng_consumer_init_command(ctx,
				msg.u.init.sessiond_uuid);
		health_code_update();
		ret = consumer_send_status_msg(sock, ret_code);
		if (ret < 0) {
			/* Somehow, the session daemon is not responding anymore. */
			goto end_nosignal;
		}
		break;
	}
	case LTTNG_CONSUMER_CREATE_TRACE_CHUNK:
	{
		const struct lttng_credentials credentials = {
			.uid = msg.u.create_trace_chunk.credentials.value.uid,
			.gid = msg.u.create_trace_chunk.credentials.value.gid,
		};
		const bool is_local_trace =
				!msg.u.create_trace_chunk.relayd_id.is_set;
		const uint64_t relayd_id =
				msg.u.create_trace_chunk.relayd_id.value;
		const char *chunk_override_name =
				*msg.u.create_trace_chunk.override_name ?
					msg.u.create_trace_chunk.override_name :
					NULL;
		struct lttng_directory_handle *chunk_directory_handle = NULL;

		/*
		 * The session daemon will only provide a chunk directory file
		 * descriptor for local traces.
		 */
		if (is_local_trace) {
			int chunk_dirfd;

			/* Acnowledge the reception of the command. */
			ret = consumer_send_status_msg(sock,
					LTTCOMM_CONSUMERD_SUCCESS);
			if (ret < 0) {
				/* Somehow, the session daemon is not responding anymore. */
				goto end_nosignal;
			}

			/*
			 * Receive trace chunk domain dirfd.
			 */
			ret = lttcomm_recv_fds_unix_sock(sock, &chunk_dirfd, 1);
			if (ret != sizeof(chunk_dirfd)) {
				ERR("Failed to receive trace chunk domain directory file descriptor");
				goto error_fatal;
			}

			DBG("Received trace chunk domain directory fd (%d)",
					chunk_dirfd);
			chunk_directory_handle = lttng_directory_handle_create_from_dirfd(
					chunk_dirfd);
			if (!chunk_directory_handle) {
				ERR("Failed to initialize chunk domain directory handle from directory file descriptor");
				if (close(chunk_dirfd)) {
					PERROR("Failed to close chunk directory file descriptor");
				}
				goto error_fatal;
			}
		}

		ret_code = lttng_consumer_create_trace_chunk(
				!is_local_trace ? &relayd_id : NULL,
				msg.u.create_trace_chunk.session_id,
				msg.u.create_trace_chunk.chunk_id,
				(time_t) msg.u.create_trace_chunk
						.creation_timestamp,
				chunk_override_name,
				msg.u.create_trace_chunk.credentials.is_set ?
						&credentials :
						NULL,
				chunk_directory_handle);
		lttng_directory_handle_put(chunk_directory_handle);
		goto end_msg_sessiond;
	}
	case LTTNG_CONSUMER_CLOSE_TRACE_CHUNK:
	{
		enum lttng_trace_chunk_command_type close_command =
				msg.u.close_trace_chunk.close_command.value;
		const uint64_t relayd_id =
				msg.u.close_trace_chunk.relayd_id.value;
		struct lttcomm_consumer_close_trace_chunk_reply reply;
		char closed_trace_chunk_path[LTTNG_PATH_MAX];
		int ret;

		ret_code = lttng_consumer_close_trace_chunk(
				msg.u.close_trace_chunk.relayd_id.is_set ?
						&relayd_id :
						NULL,
				msg.u.close_trace_chunk.session_id,
				msg.u.close_trace_chunk.chunk_id,
				(time_t) msg.u.close_trace_chunk.close_timestamp,
				msg.u.close_trace_chunk.close_command.is_set ?
						&close_command :
						NULL, closed_trace_chunk_path);
		reply.ret_code = ret_code;
		reply.path_length = strlen(closed_trace_chunk_path) + 1;
		ret = lttcomm_send_unix_sock(sock, &reply, sizeof(reply));
		if (ret != sizeof(reply)) {
			goto error_fatal;
		}
		ret = lttcomm_send_unix_sock(sock, closed_trace_chunk_path,
				reply.path_length);
		if (ret != reply.path_length) {
			goto error_fatal;
		}
		goto end_nosignal;
	}
	case LTTNG_CONSUMER_TRACE_CHUNK_EXISTS:
	{
		const uint64_t relayd_id =
				msg.u.trace_chunk_exists.relayd_id.value;

		ret_code = lttng_consumer_trace_chunk_exists(
				msg.u.trace_chunk_exists.relayd_id.is_set ?
						&relayd_id : NULL,
				msg.u.trace_chunk_exists.session_id,
				msg.u.trace_chunk_exists.chunk_id);
		goto end_msg_sessiond;
	}
	default:
		break;
	}

end_nosignal:
	/*
	 * Return 1 to indicate success since the 0 value can be a socket
	 * shutdown during the recv() or send() call.
	 */
	ret = 1;
	goto end;

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
	ret = 1;
	goto end;

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
	ret = 1;
	goto end;

error_fatal:
	/* This will issue a consumer stop. */
	ret = -1;
	goto end;

end:
	rcu_read_unlock();
	health_code_update();
	return ret;
}

void lttng_ustctl_flush_buffer(struct lttng_consumer_stream *stream,
		int producer_active)
{
	assert(stream);
	assert(stream->ustream);

	ustctl_flush_buffer(stream->ustream, producer_active);
}

/*
 * Take a snapshot for a specific stream.
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
 * Sample consumed and produced positions for a specific stream.
 *
 * Returns 0 on success, < 0 on error.
 */
int lttng_ustconsumer_sample_snapshot_positions(
		struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	return ustctl_snapshot_sample_positions(stream->ustream);
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

void lttng_ustconsumer_flush_buffer(struct lttng_consumer_stream *stream,
		int producer)
{
	assert(stream);
	assert(stream->ustream);

	ustctl_flush_buffer(stream->ustream, producer);
}

void lttng_ustconsumer_clear_buffer(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	ustctl_clear_buffer(stream->ustream);
}

int lttng_ustconsumer_get_current_timestamp(
		struct lttng_consumer_stream *stream, uint64_t *ts)
{
	assert(stream);
	assert(stream->ustream);
	assert(ts);

	return ustctl_get_current_timestamp(stream->ustream, ts);
}

int lttng_ustconsumer_get_sequence_number(
		struct lttng_consumer_stream *stream, uint64_t *seq)
{
	assert(stream);
	assert(stream->ustream);
	assert(seq);

	return ustctl_get_sequence_number(stream->ustream, seq);
}

/*
 * Called when the stream signals the consumer that it has hung up.
 */
void lttng_ustconsumer_on_stream_hangup(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	pthread_mutex_lock(&stream->lock);
	if (!stream->quiescent) {
		ustctl_flush_buffer(stream->ustream, 0);
		stream->quiescent = true;
	}
	pthread_mutex_unlock(&stream->lock);
	stream->hangup_flush_done = 1;
}

void lttng_ustconsumer_del_channel(struct lttng_consumer_channel *chan)
{
	int i;

	assert(chan);
	assert(chan->uchan);
	assert(chan->buffer_credentials.is_set);

	if (chan->switch_timer_enabled == 1) {
		consumer_timer_switch_stop(chan);
	}
	for (i = 0; i < chan->nr_stream_fds; i++) {
		int ret;

		ret = close(chan->stream_fds[i]);
		if (ret) {
			PERROR("close");
		}
		if (chan->shm_path[0]) {
			char shm_path[PATH_MAX];

			ret = get_stream_shm_path(shm_path, chan->shm_path, i);
			if (ret) {
				ERR("Cannot get stream shm path");
			}
			ret = run_as_unlink(shm_path,
					chan->buffer_credentials.value.uid,
					chan->buffer_credentials.value.gid);
			if (ret) {
				PERROR("unlink %s", shm_path);
			}
		}
	}
}

void lttng_ustconsumer_free_channel(struct lttng_consumer_channel *chan)
{
	assert(chan);
	assert(chan->uchan);
	assert(chan->buffer_credentials.is_set);

	consumer_metadata_cache_destroy(chan);
	ustctl_destroy_channel(chan->uchan);
	/* Try to rmdir all directories under shm_path root. */
	if (chan->root_shm_path[0]) {
		(void) run_as_rmdir_recursive(chan->root_shm_path,
				chan->buffer_credentials.value.uid,
				chan->buffer_credentials.value.gid,
				LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	}
	free(chan->stream_fds);
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

int lttng_ustconsumer_get_wakeup_fd(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	return ustctl_stream_get_wakeup_fd(stream->ustream);
}

int lttng_ustconsumer_close_wakeup_fd(struct lttng_consumer_stream *stream)
{
	assert(stream);
	assert(stream->ustream);

	return ustctl_stream_close_wakeup_fd(stream->ustream);
}

static
void metadata_stream_reset_cache_consumed_position(
		struct lttng_consumer_stream *stream)
{
	DBG("Reset metadata cache of session %" PRIu64,
			stream->chan->session_id);
	stream->ust_metadata_pushed = 0;
}

/*
 * Write up to one packet from the metadata cache to the channel.
 *
 * Returns the number of bytes pushed from the cache into the ring buffer, or a
 * negative value on error.
 */
static
int commit_one_metadata_packet(struct lttng_consumer_stream *stream)
{
	ssize_t write_len;
	int ret;

	pthread_mutex_lock(&stream->chan->metadata_cache->lock);
	if (stream->chan->metadata_cache->max_offset ==
	    stream->ust_metadata_pushed) {
		/*
		 * In the context of a user space metadata channel, a
		 * change in version can be detected in two ways:
		 *   1) During the pre-consume of the `read_subbuffer` loop,
		 *   2) When populating the metadata ring buffer (i.e. here).
		 *
		 * This function is invoked when there is no metadata
		 * available in the ring-buffer. If all data was consumed
		 * up to the size of the metadata cache, there is no metadata
		 * to insert in the ring-buffer.
		 *
		 * However, the metadata version could still have changed (a
		 * regeneration without any new data will yield the same cache
		 * size).
		 *
		 * The cache's version is checked for a version change and the
		 * consumed position is reset if one occurred.
		 *
		 * This check is only necessary for the user space domain as
		 * it has to manage the cache explicitly. If this reset was not
		 * performed, no metadata would be consumed (and no reset would
		 * occur as part of the pre-consume) until the metadata size
		 * exceeded the cache size.
		 */
		if (stream->metadata_version !=
				stream->chan->metadata_cache->version) {
			metadata_stream_reset_cache_consumed_position(stream);
			consumer_stream_metadata_set_version(stream,
					stream->chan->metadata_cache->version);
		} else {
			ret = 0;
			goto end;
		}
	}

	write_len = ustctl_write_one_packet_to_channel(stream->chan->uchan,
			&stream->chan->metadata_cache->data[stream->ust_metadata_pushed],
			stream->chan->metadata_cache->max_offset
			- stream->ust_metadata_pushed);
	assert(write_len != 0);
	if (write_len < 0) {
		ERR("Writing one metadata packet");
		ret = write_len;
		goto end;
	}
	stream->ust_metadata_pushed += write_len;

	assert(stream->chan->metadata_cache->max_offset >=
			stream->ust_metadata_pushed);
	ret = write_len;

	/*
	 * Switch packet (but don't open the next one) on every commit of
	 * a metadata packet. Since the subbuffer is fully filled (with padding,
	 * if needed), the stream is "quiescent" after this commit.
	 */
	ustctl_flush_buffer(stream->ustream, 1);
	stream->quiescent = true;
end:
	pthread_mutex_unlock(&stream->chan->metadata_cache->lock);
	return ret;
}


/*
 * Sync metadata meaning request them to the session daemon and snapshot to the
 * metadata thread can consumer them.
 *
 * Metadata stream lock is held here, but we need to release it when
 * interacting with sessiond, else we cause a deadlock with live
 * awaiting on metadata to be pushed out.
 *
 * The RCU read side lock must be held by the caller.
 */
enum sync_metadata_status lttng_ustconsumer_sync_metadata(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *metadata_stream)
{
	int ret;
	enum sync_metadata_status status;
	struct lttng_consumer_channel *metadata_channel;

	assert(ctx);
	assert(metadata_stream);

	metadata_channel = metadata_stream->chan;
	pthread_mutex_unlock(&metadata_stream->lock);
	/*
	 * Request metadata from the sessiond, but don't wait for the flush
	 * because we locked the metadata thread.
	 */
	ret = lttng_ustconsumer_request_metadata(ctx, metadata_channel, 0, 0);
	pthread_mutex_lock(&metadata_stream->lock);
	if (ret < 0) {
		status = SYNC_METADATA_STATUS_ERROR;
		goto end;
	}

	/*
	 * The metadata stream and channel can be deleted while the
	 * metadata stream lock was released. The streamed is checked
	 * for deletion before we use it further.
	 *
	 * Note that it is safe to access a logically-deleted stream since its
	 * existence is still guaranteed by the RCU read side lock. However,
	 * it should no longer be used. The close/deletion of the metadata
	 * channel and stream already guarantees that all metadata has been
	 * consumed. Therefore, there is nothing left to do in this function.
	 */
	if (consumer_stream_is_deleted(metadata_stream)) {
		DBG("Metadata stream %" PRIu64 " was deleted during the metadata synchronization",
				metadata_stream->key);
		status = SYNC_METADATA_STATUS_NO_DATA;
		goto end;
	}

	ret = commit_one_metadata_packet(metadata_stream);
	if (ret < 0) {
		status = SYNC_METADATA_STATUS_ERROR;
		goto end;
	} else if (ret > 0) {
		status = SYNC_METADATA_STATUS_NEW_DATA;
	} else /* ret == 0 */ {
		status = SYNC_METADATA_STATUS_NO_DATA;
		goto end;
	}

	ret = ustctl_snapshot(metadata_stream->ustream);
	if (ret < 0) {
		ERR("Failed to take a snapshot of the metadata ring-buffer positions, ret = %d", ret);
		status = SYNC_METADATA_STATUS_ERROR;
		goto end;
	}

end:
	return status;
}

/*
 * Return 0 on success else a negative value.
 */
static int notify_if_more_data(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	int ret;
	struct ustctl_consumer_stream *ustream;

	assert(stream);
	assert(ctx);

	ustream = stream->ustream;

	/*
	 * First, we are going to check if there is a new subbuffer available
	 * before reading the stream wait_fd.
	 */
	/* Get the next subbuffer */
	ret = ustctl_get_next_subbuf(ustream);
	if (ret) {
		/* No more data found, flag the stream. */
		stream->has_data = 0;
		ret = 0;
		goto end;
	}

	ret = ustctl_put_subbuf(ustream);
	assert(!ret);

	/* This stream still has data. Flag it and wake up the data thread. */
	stream->has_data = 1;

	if (stream->monitor && !stream->hangup_flush_done && !ctx->has_wakeup) {
		ssize_t writelen;

		writelen = lttng_pipe_write(ctx->consumer_wakeup_pipe, "!", 1);
		if (writelen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			ret = writelen;
			goto end;
		}

		/* The wake up pipe has been notified. */
		ctx->has_wakeup = 1;
	}
	ret = 0;

end:
	return ret;
}

static int consumer_stream_ust_on_wake_up(struct lttng_consumer_stream *stream)
{
	int ret = 0;

	/*
	 * We can consume the 1 byte written into the wait_fd by
	 * UST. Don't trigger error if we cannot read this one byte
	 * (read returns 0), or if the error is EAGAIN or EWOULDBLOCK.
	 *
	 * This is only done when the stream is monitored by a thread,
	 * before the flush is done after a hangup and if the stream
	 * is not flagged with data since there might be nothing to
	 * consume in the wait fd but still have data available
	 * flagged by the consumer wake up pipe.
	 */
	if (stream->monitor && !stream->hangup_flush_done && !stream->has_data) {
		char dummy;
		ssize_t readlen;

		readlen = lttng_read(stream->wait_fd, &dummy, 1);
		if (readlen < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			ret = readlen;
		}
	}

	return ret;
}

static int extract_common_subbuffer_info(struct lttng_consumer_stream *stream,
		struct stream_subbuffer *subbuf)
{
	int ret;

	ret = ustctl_get_subbuf_size(
			stream->ustream, &subbuf->info.data.subbuf_size);
	if (ret) {
		goto end;
	}

	ret = ustctl_get_padded_subbuf_size(
			stream->ustream, &subbuf->info.data.padded_subbuf_size);
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

	subbuf->info.metadata.version = stream->metadata_version;

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

	ret = ustctl_get_packet_size(
			stream->ustream, &subbuf->info.data.packet_size);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer packet size");
		goto end;
	}

	ret = ustctl_get_content_size(
			stream->ustream, &subbuf->info.data.content_size);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer content size");
		goto end;
	}

	ret = ustctl_get_timestamp_begin(
			stream->ustream, &subbuf->info.data.timestamp_begin);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer begin timestamp");
		goto end;
	}

	ret = ustctl_get_timestamp_end(
			stream->ustream, &subbuf->info.data.timestamp_end);
	if (ret < 0) {
		PERROR("Failed to get sub-buffer end timestamp");
		goto end;
	}

	ret = ustctl_get_events_discarded(
			stream->ustream, &subbuf->info.data.events_discarded);
	if (ret) {
		PERROR("Failed to get sub-buffer events discarded count");
		goto end;
	}

	ret = ustctl_get_sequence_number(stream->ustream,
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

	ret = ustctl_get_stream_id(
			stream->ustream, &subbuf->info.data.stream_id);
	if (ret < 0) {
		PERROR("Failed to get stream id");
		goto end;
	}

	ret = ustctl_get_instance_id(stream->ustream,
			&subbuf->info.data.stream_instance_id.value);
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

static int get_next_subbuffer_common(struct lttng_consumer_stream *stream,
		struct stream_subbuffer *subbuffer)
{
	int ret;
	const char *addr;

	ret = stream->read_subbuffer_ops.extract_subbuffer_info(
			stream, subbuffer);
	if (ret) {
		goto end;
	}

	ret = get_current_subbuf_addr(stream, &addr);
	if (ret) {
		goto end;
	}

	subbuffer->buffer.buffer = lttng_buffer_view_init(
			addr, 0, subbuffer->info.data.padded_subbuf_size);
	assert(subbuffer->buffer.buffer.data != NULL);
end:
	return ret;
}

static int get_next_subbuffer(struct lttng_consumer_stream *stream,
		struct stream_subbuffer *subbuffer)
{
	int ret;

	ret = ustctl_get_next_subbuf(stream->ustream);
	if (ret) {
		goto end;
	}

	ret = get_next_subbuffer_common(stream, subbuffer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static int get_next_subbuffer_metadata(struct lttng_consumer_stream *stream,
		struct stream_subbuffer *subbuffer)
{
	int ret;
	bool cache_empty;
	bool got_subbuffer;
	bool coherent;
	bool buffer_empty;
	unsigned long consumed_pos, produced_pos;

	do {
		ret = ustctl_get_next_subbuf(stream->ustream);
		if (ret == 0) {
			got_subbuffer = true;
		} else {
			got_subbuffer = false;
			if (ret != -EAGAIN) {
				/* Fatal error. */
				goto end;
			}
		}

		/*
		 * Determine if the cache is empty and ensure that a sub-buffer
		 * is made available if the cache is not empty.
		 */
		if (!got_subbuffer) {
			ret = commit_one_metadata_packet(stream);
			if (ret < 0 && ret != -ENOBUFS) {
				goto end;
			} else if (ret == 0) {
				/* Not an error, the cache is empty. */
				cache_empty = true;
				ret = -ENODATA;
				goto end;
			} else {
				cache_empty = false;
			}
		} else {
			pthread_mutex_lock(&stream->chan->metadata_cache->lock);
			cache_empty = stream->chan->metadata_cache->max_offset ==
				      stream->ust_metadata_pushed;
			pthread_mutex_unlock(&stream->chan->metadata_cache->lock);
		}
	} while (!got_subbuffer);

	/* Populate sub-buffer infos and view. */
	ret = get_next_subbuffer_common(stream, subbuffer);
	if (ret) {
		goto end;
	}

	ret = lttng_ustconsumer_sample_snapshot_positions(stream);
	if (ret < 0) {
		/*
		 * -EAGAIN is not expected since we got a sub-buffer and haven't
		 * pushed the consumption position yet (on put_next).
		 */
		PERROR("Failed to take a snapshot of metadata buffer positions");
		goto end;
	}

	ret = lttng_ustconsumer_get_consumed_snapshot(stream, &consumed_pos);
	if (ret) {
		PERROR("Failed to get metadata consumed position");
		goto end;
	}

	ret = lttng_ustconsumer_get_produced_snapshot(stream, &produced_pos);
	if (ret) {
		PERROR("Failed to get metadata produced position");
		goto end;
	}

	/* Last sub-buffer of the ring buffer ? */
	buffer_empty = (consumed_pos + stream->max_sb_size) == produced_pos;

	/*
	 * The sessiond registry lock ensures that coherent units of metadata
	 * are pushed to the consumer daemon at once. Hence, if a sub-buffer is
	 * acquired, the cache is empty, and it is the only available sub-buffer
	 * available, it is safe to assume that it is "coherent".
	 */
	coherent = got_subbuffer && cache_empty && buffer_empty;

	LTTNG_OPTIONAL_SET(&subbuffer->info.metadata.coherent, coherent);
end:
	return ret;
}

static int put_next_subbuffer(struct lttng_consumer_stream *stream,
		struct stream_subbuffer *subbuffer)
{
	const int ret = ustctl_put_next_subbuf(stream->ustream);

	assert(ret == 0);
	return ret;
}

static int signal_metadata(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	return pthread_cond_broadcast(&stream->metadata_rdv) ? -errno : 0;
}

static int lttng_ustconsumer_set_stream_ops(
		struct lttng_consumer_stream *stream)
{
	int ret = 0;

	stream->read_subbuffer_ops.on_wake_up = consumer_stream_ust_on_wake_up;
	if (stream->metadata_flag) {
		stream->read_subbuffer_ops.get_next_subbuffer =
				get_next_subbuffer_metadata;
		stream->read_subbuffer_ops.extract_subbuffer_info =
				extract_metadata_subbuffer_info;
		stream->read_subbuffer_ops.reset_metadata =
				metadata_stream_reset_cache_consumed_position;
		if (stream->chan->is_live) {
			stream->read_subbuffer_ops.on_sleep = signal_metadata;
			ret = consumer_stream_enable_metadata_bucketization(
					stream);
			if (ret) {
				goto end;
			}
		}
	} else {
		stream->read_subbuffer_ops.get_next_subbuffer =
				get_next_subbuffer;
		stream->read_subbuffer_ops.extract_subbuffer_info =
				extract_data_subbuffer_info;
		stream->read_subbuffer_ops.on_sleep = notify_if_more_data;
		if (stream->chan->is_live) {
			stream->read_subbuffer_ops.send_live_beacon =
					consumer_flush_ust_index;
		}
	}

	stream->read_subbuffer_ops.put_next_subbuffer = put_next_subbuffer;
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

	lttng_ustconsumer_set_stream_ops(stream);
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

	if (stream->chan->type == CONSUMER_CHANNEL_TYPE_METADATA) {
		uint64_t contiguous, pushed;

		/* Ease our life a bit. */
		contiguous = stream->chan->metadata_cache->max_offset;
		pushed = stream->ust_metadata_pushed;

		/*
		 * We can simply check whether all contiguously available data
		 * has been pushed to the ring buffer, since the push operation
		 * is performed within get_next_subbuf(), and because both
		 * get_next_subbuf() and put_next_subbuf() are issued atomically
		 * thanks to the stream lock within
		 * lttng_ustconsumer_read_subbuffer(). This basically means that
		 * whetnever ust_metadata_pushed is incremented, the associated
		 * metadata has been consumed from the metadata stream.
		 */
		DBG("UST consumer metadata pending check: contiguous %" PRIu64 " vs pushed %" PRIu64,
				contiguous, pushed);
		assert(((int64_t) (contiguous - pushed)) >= 0);
		if ((contiguous != pushed) ||
				(((int64_t) contiguous - pushed) > 0 || contiguous == 0)) {
			ret = 1;	/* Data is pending */
			goto end;
		}
	} else {
		ret = ustctl_get_next_subbuf(stream->ustream);
		if (ret == 0) {
			/*
			 * There is still data so let's put back this
			 * subbuffer.
			 */
			ret = ustctl_put_subbuf(stream->ustream);
			assert(ret == 0);
			ret = 1;	/* Data is pending */
			goto end;
		}
	}

	/* Data is NOT pending so ready to be read. */
	ret = 0;

end:
	return ret;
}

/*
 * Stop a given metadata channel timer if enabled and close the wait fd which
 * is the poll pipe of the metadata stream.
 *
 * This MUST be called with the metadata channel lock acquired.
 */
void lttng_ustconsumer_close_metadata(struct lttng_consumer_channel *metadata)
{
	int ret;

	assert(metadata);
	assert(metadata->type == CONSUMER_CHANNEL_TYPE_METADATA);

	DBG("Closing metadata channel key %" PRIu64, metadata->key);

	if (metadata->switch_timer_enabled == 1) {
		consumer_timer_switch_stop(metadata);
	}

	if (!metadata->metadata_stream) {
		goto end;
	}

	/*
	 * Closing write side so the thread monitoring the stream wakes up if any
	 * and clean the metadata stream.
	 */
	if (metadata->metadata_stream->ust_metadata_poll_pipe[1] >= 0) {
		ret = close(metadata->metadata_stream->ust_metadata_poll_pipe[1]);
		if (ret < 0) {
			PERROR("closing metadata pipe write side");
		}
		metadata->metadata_stream->ust_metadata_poll_pipe[1] = -1;
	}

end:
	return;
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
void lttng_ustconsumer_close_all_metadata(struct lttng_ht *metadata_ht)
{
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;

	assert(metadata_ht);
	assert(metadata_ht->ht);

	DBG("UST consumer closing all metadata streams");

	rcu_read_lock();
	cds_lfht_for_each_entry(metadata_ht->ht, &iter.iter, stream,
			node.node) {

		health_code_update();

		pthread_mutex_lock(&stream->chan->lock);
		lttng_ustconsumer_close_metadata(stream->chan);
		pthread_mutex_unlock(&stream->chan->lock);

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

/*
 * Please refer to consumer-timer.c before adding any lock within this
 * function or any of its callees. Timers have a very strict locking
 * semantic with respect to teardown. Failure to respect this semantic
 * introduces deadlocks.
 *
 * DON'T hold the metadata lock when calling this function, else this
 * can cause deadlock involving consumer awaiting for metadata to be
 * pushed out due to concurrent interaction with the session daemon.
 */
int lttng_ustconsumer_request_metadata(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_channel *channel, int timer, int wait)
{
	struct lttcomm_metadata_request_msg request;
	struct lttcomm_consumer_msg msg;
	enum lttcomm_return_code ret_code = LTTCOMM_CONSUMERD_SUCCESS;
	uint64_t len, key, offset, version;
	int ret;

	assert(channel);
	assert(channel->metadata_cache);

	memset(&request, 0, sizeof(request));

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
	/*
	 * Request the application UID here so the metadata of that application can
	 * be sent back. The channel UID corresponds to the user UID of the session
	 * used for the rights on the stream file(s).
	 */
	request.uid = channel->ust_app_uid;
	request.key = channel->key;

	DBG("Sending metadata request to sessiond, session id %" PRIu64
			", per-pid %" PRIu64 ", app UID %u and channel key %" PRIu64,
			request.session_id, request.session_id_per_pid, request.uid,
			request.key);

	pthread_mutex_lock(&ctx->metadata_socket_lock);

	health_code_update();

	ret = lttcomm_send_unix_sock(ctx->consumer_metadata_socket, &request,
			sizeof(request));
	if (ret < 0) {
		ERR("Asking metadata to sessiond");
		goto end;
	}

	health_code_update();

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

	health_code_update();

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
	version = msg.u.push_metadata.version;

	assert(key == channel->key);
	if (len == 0) {
		DBG("No new metadata to receive for key %" PRIu64, key);
	}

	health_code_update();

	/* Tell session daemon we are ready to receive the metadata. */
	ret = consumer_send_status_msg(ctx->consumer_metadata_socket,
			LTTCOMM_CONSUMERD_SUCCESS);
	if (ret < 0 || len == 0) {
		/*
		 * Somehow, the session daemon is not responding anymore or there is
		 * nothing to receive.
		 */
		goto end;
	}

	health_code_update();

	ret = lttng_ustconsumer_recv_metadata(ctx->consumer_metadata_socket,
			key, offset, len, version, channel, timer, wait);
	if (ret >= 0) {
		/*
		 * Only send the status msg if the sessiond is alive meaning a positive
		 * ret code.
		 */
		(void) consumer_send_status_msg(ctx->consumer_metadata_socket, ret);
	}
	ret = 0;

end:
	health_code_update();

	pthread_mutex_unlock(&ctx->metadata_socket_lock);
	return ret;
}

/*
 * Return the ustctl call for the get stream id.
 */
int lttng_ustconsumer_get_stream_id(struct lttng_consumer_stream *stream,
		uint64_t *stream_id)
{
	assert(stream);
	assert(stream_id);

	return ustctl_get_stream_id(stream->ustream, stream_id);
}
