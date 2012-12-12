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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <common/common.h>
#include <common/defaults.h>

#include "consumer.h"
#include "kernel-consumer.h"

/*
 * Sending a single channel to the consumer with command ADD_CHANNEL.
 */
int kernel_consumer_add_channel(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel)
{
	int ret;
	struct lttcomm_consumer_msg lkm;

	/* Safety net */
	assert(channel);

	DBG("Kernel consumer adding channel %s to kernel consumer",
			channel->channel->name);

	/* Prep channel message structure */
	consumer_init_channel_comm_msg(&lkm,
			LTTNG_CONSUMER_ADD_CHANNEL,
			channel->fd,
			channel->channel->attr.subbuf_size,
			0, /* Kernel */
			channel->channel->name,
			channel->stream_count);

	ret = consumer_send_channel(sock, &lkm);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Sending metadata to the consumer with command ADD_CHANNEL and ADD_STREAM.
 */
int kernel_consumer_add_metadata(struct consumer_socket *sock,
		struct ltt_kernel_session *session)
{
	int ret;
	char tmp_path[PATH_MAX];
	const char *pathname;
	struct lttcomm_consumer_msg lkm;
	struct consumer_output *consumer;

	/* Safety net */
	assert(session);
	assert(session->consumer);
	assert(sock);

	DBG("Sending metadata %d to kernel consumer", session->metadata_stream_fd);

	/* Get consumer output pointer */
	consumer = session->consumer;

	/* Get the right path name destination */
	if (consumer->type == CONSUMER_DST_LOCAL) {
		/* Set application path to the destination path */
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
				consumer->dst.trace_path, consumer->subdir);
		if (ret < 0) {
			PERROR("snprintf metadata path");
			goto error;
		}
		pathname = tmp_path;

		/* Create directory */
		ret = run_as_mkdir_recursive(pathname, S_IRWXU | S_IRWXG,
				session->uid, session->gid);
		if (ret < 0) {
			if (ret != -EEXIST) {
				ERR("Trace directory creation error");
				goto error;
			}
		}
		DBG3("Kernel local consumer tracefile path: %s", pathname);
	} else {
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s", consumer->subdir);
		if (ret < 0) {
			PERROR("snprintf metadata path");
			goto error;
		}
		pathname = tmp_path;
		DBG3("Kernel network consumer subdir path: %s", pathname);
	}

	/* Prep channel message structure */
	consumer_init_channel_comm_msg(&lkm,
			LTTNG_CONSUMER_ADD_CHANNEL,
			session->metadata->fd,
			session->metadata->conf->attr.subbuf_size,
			0, /* for kernel */
			"metadata",
			1);

	ret = consumer_send_channel(sock, &lkm);
	if (ret < 0) {
		goto error;
	}

	/* Prep stream message structure */
	consumer_init_stream_comm_msg(&lkm,
			LTTNG_CONSUMER_ADD_STREAM,
			session->metadata->fd,
			session->metadata_stream_fd,
			LTTNG_CONSUMER_ACTIVE_STREAM,
			DEFAULT_KERNEL_CHANNEL_OUTPUT,
			0, /* Kernel */
			session->uid,
			session->gid,
			consumer->net_seq_index,
			1, /* Metadata flag set */
			"metadata",
			pathname,
			session->id);

	/* Send stream and file descriptor */
	ret = consumer_send_stream(sock, consumer, &lkm,
			&session->metadata_stream_fd, 1);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Sending a single stream to the consumer with command ADD_STREAM.
 */
int kernel_consumer_add_stream(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel, struct ltt_kernel_stream *stream,
		struct ltt_kernel_session *session)
{
	int ret;
	char tmp_path[PATH_MAX];
	const char *pathname;
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

	/* Get the right path name destination */
	if (consumer->type == CONSUMER_DST_LOCAL) {
		/* Set application path to the destination path */
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
				consumer->dst.trace_path, consumer->subdir);
		if (ret < 0) {
			PERROR("snprintf stream path");
			goto error;
		}
		pathname = tmp_path;
		DBG3("Kernel local consumer tracefile path: %s", pathname);
	} else {
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s", consumer->subdir);
		if (ret < 0) {
			PERROR("snprintf stream path");
			goto error;
		}
		pathname = tmp_path;
		DBG3("Kernel network consumer subdir path: %s", pathname);
	}

	/* Prep stream consumer message */
	consumer_init_stream_comm_msg(&lkm, LTTNG_CONSUMER_ADD_STREAM,
			channel->fd,
			stream->fd,
			stream->state,
			channel->channel->attr.output,
			0, /* Kernel */
			session->uid,
			session->gid,
			consumer->net_seq_index,
			0, /* Metadata flag unset */
			stream->name,
			pathname,
			session->id);

	/* Send stream and file descriptor */
	ret = consumer_send_stream(sock, consumer, &lkm, &stream->fd, 1);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send all stream fds of kernel channel to the consumer.
 */
int kernel_consumer_send_channel_stream(struct consumer_socket *sock,
		struct ltt_kernel_channel *channel, struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_stream *stream;

	/* Safety net */
	assert(channel);
	assert(session);
	assert(session->consumer);
	assert(sock);

	/* Bail out if consumer is disabled */
	if (!session->consumer->enabled) {
		ret = LTTNG_OK;
		goto error;
	}

	DBG("Sending streams of channel %s to kernel consumer",
			channel->channel->name);

	ret = kernel_consumer_add_channel(sock, channel);
	if (ret < 0) {
		goto error;
	}

	/* Send streams */
	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		if (!stream->fd) {
			continue;
		}

		/* Add stream on the kernel consumer side. */
		ret = kernel_consumer_add_stream(sock, channel, stream, session);
		if (ret < 0) {
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Send all stream fds of the kernel session to the consumer.
 */
int kernel_consumer_send_session(struct consumer_socket *sock,
		struct ltt_kernel_session *session)
{
	int ret;
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

	DBG("Sending session stream to kernel consumer");

	if (session->metadata_stream_fd >= 0) {
		ret = kernel_consumer_add_metadata(sock, session);
		if (ret < 0) {
			goto error;
		}

		/* Flag that at least the metadata has been sent to the consumer. */
		session->consumer_fds_sent = 1;
	}

	/* Send channel and streams of it */
	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		ret = kernel_consumer_send_channel_stream(sock, chan, session);
		if (ret < 0) {
			goto error;
		}
	}

	DBG("Kernel consumer FDs of metadata and channel streams sent");

	return 0;

error:
	return ret;
}
