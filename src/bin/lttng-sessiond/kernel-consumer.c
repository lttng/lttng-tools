/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/compat/string.h>

#include "consumer.h"
#include "health-sessiond.h"
#include "kernel-consumer.h"
#include "notification-thread-commands.h"
#include "session.h"
#include "lttng-sessiond.h"

static char *create_channel_path(struct consumer_output *consumer)
{
	int ret;
	char tmp_path[PATH_MAX];
	char *pathname = NULL;

	assert(consumer);

	/* Get the right path name destination */
	if (consumer->type == CONSUMER_DST_LOCAL) {
		pathname = strdup(consumer->domain_subdir);
		if (!pathname) {
			PERROR("Failed to copy domain subdirectory string %s",
					consumer->domain_subdir);
			goto error;
		}
		DBG3("Kernel local consumer trace path relative to current trace chunk: \"%s\"",
				pathname);
	} else {
		/* Network output. */
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s%s",
				consumer->dst.net.base_dir,
				consumer->domain_subdir);
		if (ret < 0) {
			PERROR("snprintf kernel metadata path");
			goto error;
		} else if (ret >= sizeof(tmp_path)) {
			ERR("Kernel channel path exceeds the maximal allowed length of of %zu bytes (%i bytes required) with path \"%s%s\"",
					sizeof(tmp_path), ret,
					consumer->dst.net.base_dir,
					consumer->domain_subdir);
			goto error;
		}
		pathname = lttng_strndup(tmp_path, sizeof(tmp_path));
		if (!pathname) {
			PERROR("lttng_strndup");
			goto error;
		}
		DBG3("Kernel network consumer subdir path: %s", pathname);
	}

	return pathname;

error:
	free(pathname);
	return NULL;
}

/*
 * Sending a single channel to the consumer with command ADD_CHANNEL.
 */
static
int kernel_consumer_add_channel(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel,
		struct ltt_kernel_session *ksession,
		unsigned int monitor)
{
	int ret;
	char *pathname = NULL;
	struct lttcomm_consumer_msg lkm;
	struct consumer_output *consumer;
	enum lttng_error_code status;
	struct ltt_session *session = NULL;
	struct lttng_channel_extended *channel_attr_extended;
	bool is_local_trace;

	/* Safety net */
	assert(channel);
	assert(ksession);
	assert(ksession->consumer);

	consumer = ksession->consumer;
	channel_attr_extended = (struct lttng_channel_extended *)
			channel->channel->attr.extended.ptr;

	DBG("Kernel consumer adding channel %s to kernel consumer",
			channel->channel->name);
	is_local_trace = consumer->net_seq_index == -1ULL;

	pathname = create_channel_path(consumer);
	if (!pathname) {
		ret = -1;
		goto error;
	}

	if (is_local_trace && ksession->current_trace_chunk) {
		enum lttng_trace_chunk_status chunk_status;
		char *pathname_index;

		ret = asprintf(&pathname_index, "%s/" DEFAULT_INDEX_DIR,
				pathname);
		if (ret < 0) {
			ERR("Failed to format channel index directory");
			ret = -1;
			goto error;
		}

		/*
		 * Create the index subdirectory which will take care
		 * of implicitly creating the channel's path.
		 */
		chunk_status = lttng_trace_chunk_create_subdirectory(
				ksession->current_trace_chunk, pathname_index);
		free(pathname_index);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			goto error;
		}
	}

	/* Prep channel message structure */
	consumer_init_add_channel_comm_msg(&lkm,
			channel->key,
			ksession->id,
			pathname,
			ksession->uid,
			ksession->gid,
			consumer->net_seq_index,
			channel->channel->name,
			channel->stream_count,
			channel->channel->attr.output,
			CONSUMER_CHANNEL_TYPE_DATA,
			channel->channel->attr.tracefile_size,
			channel->channel->attr.tracefile_count,
			monitor,
			channel->channel->attr.live_timer_interval,
			channel_attr_extended->monitor_timer_interval,
			ksession->current_trace_chunk);

	health_code_update();

	ret = consumer_send_channel(sock, &lkm);
	if (ret < 0) {
		goto error;
	}

	health_code_update();
	rcu_read_lock();
	session = session_find_by_id(ksession->id);
	assert(session);
	assert(pthread_mutex_trylock(&session->lock));
	assert(session_trylock_list());

	status = notification_thread_command_add_channel(
			notification_thread_handle, session->name,
			ksession->uid, ksession->gid,
			channel->channel->name, channel->key,
			LTTNG_DOMAIN_KERNEL,
			channel->channel->attr.subbuf_size * channel->channel->attr.num_subbuf);
	rcu_read_unlock();
	if (status != LTTNG_OK) {
		ret = -1;
		goto error;
	}

	channel->published_to_notification_thread = true;

error:
	if (session) {
		session_put(session);
	}
	free(pathname);
	return ret;
}

/*
 * Sending metadata to the consumer with command ADD_CHANNEL and ADD_STREAM.
 *
 * The consumer socket lock must be held by the caller.
 */
int kernel_consumer_add_metadata(struct consumer_socket *sock,
		struct ltt_kernel_session *ksession, unsigned int monitor)
{
	int ret;
	struct lttcomm_consumer_msg lkm;
	struct consumer_output *consumer;

	rcu_read_lock();

	/* Safety net */
	assert(ksession);
	assert(ksession->consumer);
	assert(sock);

	DBG("Sending metadata %d to kernel consumer",
			ksession->metadata_stream_fd);

	/* Get consumer output pointer */
	consumer = ksession->consumer;

	/* Prep channel message structure */
	consumer_init_add_channel_comm_msg(&lkm,
			ksession->metadata->key,
			ksession->id,
			DEFAULT_KERNEL_TRACE_DIR,
			ksession->uid,
			ksession->gid,
			consumer->net_seq_index,
			DEFAULT_METADATA_NAME,
			1,
			DEFAULT_KERNEL_CHANNEL_OUTPUT,
			CONSUMER_CHANNEL_TYPE_METADATA,
			0, 0,
			monitor, 0, 0, ksession->current_trace_chunk);

	health_code_update();

	ret = consumer_send_channel(sock, &lkm);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Prep stream message structure */
	consumer_init_add_stream_comm_msg(&lkm,
			ksession->metadata->key,
			ksession->metadata_stream_fd,
			0 /* CPU: 0 for metadata. */);

	health_code_update();

	/* Send stream and file descriptor */
	ret = consumer_send_stream(sock, consumer, &lkm,
			&ksession->metadata_stream_fd, 1);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Sending a single stream to the consumer with command ADD_STREAM.
 */
static
int kernel_consumer_add_stream(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel,
		struct ltt_kernel_stream *stream,
		struct ltt_kernel_session *session, unsigned int monitor)
{
	int ret;
	struct lttcomm_consumer_msg lkm;
	struct consumer_output *consumer;

	assert(channel);
	assert(stream);
	assert(session);
	assert(session->consumer);
	assert(sock);

	DBG("Sending stream %d of channel %s to kernel consumer",
			stream->fd, channel->channel->name);

	/* Get consumer output pointer */
	consumer = session->consumer;

	/* Prep stream consumer message */
	consumer_init_add_stream_comm_msg(&lkm,
			channel->key,
			stream->fd,
			stream->cpu);

	health_code_update();

	/* Send stream and file descriptor */
	ret = consumer_send_stream(sock, consumer, &lkm, &stream->fd, 1);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

error:
	return ret;
}

/*
 * Sending the notification that all streams were sent with STREAMS_SENT.
 */
int kernel_consumer_streams_sent(struct consumer_socket *sock,
		struct ltt_kernel_session *session, uint64_t channel_key)
{
	int ret;
	struct lttcomm_consumer_msg lkm;
	struct consumer_output *consumer;

	assert(sock);
	assert(session);

	DBG("Sending streams_sent");
	/* Get consumer output pointer */
	consumer = session->consumer;

	/* Prep stream consumer message */
	consumer_init_streams_sent_comm_msg(&lkm,
			LTTNG_CONSUMER_STREAMS_SENT,
			channel_key, consumer->net_seq_index);

	health_code_update();

	/* Send stream and file descriptor */
	ret = consumer_send_msg(sock, &lkm);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send all stream fds of kernel channel to the consumer.
 *
 * The consumer socket lock must be held by the caller.
 */
int kernel_consumer_send_channel_streams(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel, struct ltt_kernel_session *ksession,
		unsigned int monitor)
{
	int ret = LTTNG_OK;
	struct ltt_kernel_stream *stream;

	/* Safety net */
	assert(channel);
	assert(ksession);
	assert(ksession->consumer);
	assert(sock);

	rcu_read_lock();

	/* Bail out if consumer is disabled */
	if (!ksession->consumer->enabled) {
		ret = LTTNG_OK;
		goto error;
	}

	DBG("Sending streams of channel %s to kernel consumer",
			channel->channel->name);

	if (!channel->sent_to_consumer) {
		ret = kernel_consumer_add_channel(sock, channel, ksession, monitor);
		if (ret < 0) {
			goto error;
		}
		channel->sent_to_consumer = true;
	}

	/* Send streams */
	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		if (!stream->fd || stream->sent_to_consumer) {
			continue;
		}

		/* Add stream on the kernel consumer side. */
		ret = kernel_consumer_add_stream(sock, channel, stream,
				ksession, monitor);
		if (ret < 0) {
			goto error;
		}
		stream->sent_to_consumer = true;
	}

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Send all stream fds of the kernel session to the consumer.
 *
 * The consumer socket lock must be held by the caller.
 */
int kernel_consumer_send_session(struct consumer_socket *sock,
		struct ltt_kernel_session *session)
{
	int ret, monitor = 0;
	struct ltt_kernel_channel *chan;

	/* Safety net */
	assert(session);
	assert(session->consumer);
	assert(sock);

	/* Bail out if consumer is disabled */
	if (!session->consumer->enabled) {
		ret = LTTNG_OK;
		goto error;
	}

	/* Don't monitor the streams on the consumer if in flight recorder. */
	if (session->output_traces) {
		monitor = 1;
	}

	DBG("Sending session stream to kernel consumer");

	if (session->metadata_stream_fd >= 0 && session->metadata) {
		ret = kernel_consumer_add_metadata(sock, session, monitor);
		if (ret < 0) {
			goto error;
		}
	}

	/* Send channel and streams of it */
	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		ret = kernel_consumer_send_channel_streams(sock, chan, session,
				monitor);
		if (ret < 0) {
			goto error;
		}
		if (monitor) {
			/*
			 * Inform the relay that all the streams for the
			 * channel were sent.
			 */
			ret = kernel_consumer_streams_sent(sock, session, chan->key);
			if (ret < 0) {
				goto error;
			}
		}
	}

	DBG("Kernel consumer FDs of metadata and channel streams sent");

	session->consumer_fds_sent = 1;
	return 0;

error:
	return ret;
}

int kernel_consumer_destroy_channel(struct consumer_socket *socket,
		struct ltt_kernel_channel *channel)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	assert(channel);
	assert(socket);

	DBG("Sending kernel consumer destroy channel key %" PRIu64, channel->key);

	memset(&msg, 0, sizeof(msg));
	msg.cmd_type = LTTNG_CONSUMER_DESTROY_CHANNEL;
	msg.u.destroy_channel.key = channel->key;

	pthread_mutex_lock(socket->lock);
	health_code_update();

	ret = consumer_send_msg(socket, &msg);
	if (ret < 0) {
		goto error;
	}

error:
	health_code_update();
	pthread_mutex_unlock(socket->lock);
	return ret;
}

int kernel_consumer_destroy_metadata(struct consumer_socket *socket,
		struct ltt_kernel_metadata *metadata)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	assert(metadata);
	assert(socket);

	DBG("Sending kernel consumer destroy channel key %" PRIu64, metadata->key);

	memset(&msg, 0, sizeof(msg));
	msg.cmd_type = LTTNG_CONSUMER_DESTROY_CHANNEL;
	msg.u.destroy_channel.key = metadata->key;

	pthread_mutex_lock(socket->lock);
	health_code_update();

	ret = consumer_send_msg(socket, &msg);
	if (ret < 0) {
		goto error;
	}

error:
	health_code_update();
	pthread_mutex_unlock(socket->lock);
	return ret;
}
