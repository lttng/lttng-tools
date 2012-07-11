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
int kernel_consumer_add_channel(int sock, struct ltt_kernel_channel *channel)
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
			channel->channel->name);

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
int kernel_consumer_add_metadata(int sock, struct ltt_kernel_session *session)
{
	int ret;
	const char *pathname;
	struct lttcomm_consumer_msg lkm;
	struct consumer_output *output;

	/* Safety net */
	assert(session);
	assert(session->consumer);

	DBG("Sending metadata %d to kernel consumer", session->metadata_stream_fd);

	/* Get consumer output pointer */
	output = session->consumer;

	/* Get correct path name destination */
	if (output->type == CONSUMER_DST_LOCAL) {
		pathname = output->dst.trace_path;
	} else {
		pathname = output->subdir;
	}

	/* Prep channel message structure */
	consumer_init_channel_comm_msg(&lkm,
			LTTNG_CONSUMER_ADD_CHANNEL,
			session->metadata->fd,
			session->metadata->conf->attr.subbuf_size,
			0, /* for kernel */
			"metadata");

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
			output->net_seq_index,
			1, /* Metadata flag set */
			"metadata",
			pathname);

	/* Send stream and file descriptor */
	ret = consumer_send_stream(sock, output, &lkm,
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
int kernel_consumer_add_stream(int sock, struct ltt_kernel_channel *channel,
		struct ltt_kernel_stream *stream, struct ltt_kernel_session *session)
{
	int ret;
	const char *pathname;
	struct lttcomm_consumer_msg lkm;
	struct consumer_output *output;

	assert(channel);
	assert(stream);
	assert(session);
	assert(session->consumer);

	DBG("Sending stream %d of channel %s to kernel consumer",
			stream->fd, channel->channel->name);

	/* Get consumer output pointer */
	output = session->consumer;

	/* Get correct path name destination */
	if (output->type == CONSUMER_DST_LOCAL) {
		pathname = output->dst.trace_path;
		DBG3("Consumer is local to %s", pathname);
	} else {
		pathname = output->subdir;
		DBG3("Consumer is network to subdir %s", pathname);
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
			output->net_seq_index,
			0, /* Metadata flag unset */
			stream->name,
			pathname);

	/* Send stream and file descriptor */
	ret = consumer_send_stream(sock, output, &lkm, &stream->fd, 1);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send all stream fds of kernel channel to the consumer.
 */
int kernel_consumer_send_channel_stream(int sock,
		struct ltt_kernel_channel *channel, struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_stream *stream;

	/* Safety net */
	assert(channel);
	assert(session);
	assert(session->consumer);

	/* Bail out if consumer is disabled */
	if (!session->consumer->enabled) {
		ret = LTTCOMM_OK;
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
int kernel_consumer_send_session(int sock, struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_channel *chan;

	/* Safety net */
	assert(session);
	assert(session->consumer);

	/* Bail out if consumer is disabled */
	if (!session->consumer->enabled) {
		ret = LTTCOMM_OK;
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

/*
 * Send relayd socket to consumer associated with a session name.
 *
 * On success return positive value. On error, negative value.
 */
int kernel_consumer_send_relayd_socket(int consumer_sock,
		struct lttcomm_sock *sock, struct consumer_output *consumer,
		enum lttng_stream_type type)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	/* Code flow error. Safety net. */
	assert(sock);
	assert(consumer);

	/* Bail out if consumer is disabled */
	if (!consumer->enabled) {
		ret = LTTCOMM_OK;
		goto error;
	}

	msg.cmd_type = LTTNG_CONSUMER_ADD_RELAYD_SOCKET;
	/*
	 * Assign network consumer output index using the temporary consumer since
	 * this call should only be made from within a set_consumer_uri() function
	 * call in the session daemon.
	 */
	msg.u.relayd_sock.net_index = consumer->net_seq_index;
	msg.u.relayd_sock.type = type;
	memcpy(&msg.u.relayd_sock.sock, sock, sizeof(msg.u.relayd_sock.sock));

	DBG2("Sending relayd sock info to consumer");
	ret = lttcomm_send_unix_sock(consumer_sock, &msg, sizeof(msg));
	if (ret < 0) {
		PERROR("send consumer relayd socket info");
		goto error;
	}

	DBG2("Sending relayd socket file descriptor to consumer");
	ret = consumer_send_fds(consumer_sock, &sock->fd, 1);
	if (ret < 0) {
		goto error;
	}

	DBG("Kernel consumer relayd socket sent");

error:
	return ret;
}
