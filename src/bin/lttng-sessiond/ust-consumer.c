/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <common/common.h>
#include <common/consumer.h>
#include <common/defaults.h>

#include "consumer.h"
#include "ust-consumer.h"

/*
 * Send a single channel to the consumer using command ADD_CHANNEL.
 */
static int send_channel(struct consumer_socket *sock,
		struct ust_app_channel *uchan)
{
	int ret, fd;
	struct lttcomm_consumer_msg msg;

	/* Safety net */
	assert(uchan);
	assert(sock);

	if (sock->fd < 0) {
		ret = -EINVAL;
		goto error;
	}

	DBG2("Sending channel %s to UST consumer", uchan->name);

	consumer_init_channel_comm_msg(&msg,
			LTTNG_CONSUMER_ADD_CHANNEL,
			uchan->obj->shm_fd,
			uchan->attr.subbuf_size,
			uchan->obj->memory_map_size,
			uchan->name,
			uchan->streams.count);

	ret = consumer_send_channel(sock, &msg);
	if (ret < 0) {
		goto error;
	}

	fd = uchan->obj->shm_fd;
	ret = consumer_send_fds(sock, &fd, 1);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send a single stream to the consumer using ADD_STREAM command.
 */
static int send_channel_stream(struct consumer_socket *sock,
		struct ust_app_channel *uchan, struct ust_app_session *usess,
		struct ltt_ust_stream *stream, struct consumer_output *consumer,
		const char *pathname)
{
	int ret, fds[2];
	struct lttcomm_consumer_msg msg;

	/* Safety net */
	assert(uchan);
	assert(usess);
	assert(stream);
	assert(consumer);
	assert(sock);

	DBG2("Sending stream %d of channel %s to kernel consumer",
			stream->obj->shm_fd, uchan->name);

	consumer_init_stream_comm_msg(&msg,
			LTTNG_CONSUMER_ADD_STREAM,
			uchan->obj->shm_fd,
			stream->obj->shm_fd,
			LTTNG_CONSUMER_ACTIVE_STREAM,
			DEFAULT_UST_CHANNEL_OUTPUT,
			stream->obj->memory_map_size,
			usess->uid,
			usess->gid,
			consumer->net_seq_index,
			0, /* Metadata flag unset */
			stream->name,
			pathname,
			usess->id);

	/* Send stream and file descriptor */
	fds[0] = stream->obj->shm_fd;
	fds[1] = stream->obj->wait_fd;
	ret = consumer_send_stream(sock, consumer, &msg, fds, 2);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send all stream fds of UST channel to the consumer.
 */
static int send_channel_streams(struct consumer_socket *sock,
		struct ust_app_channel *uchan, struct ust_app_session *usess,
		struct consumer_output *consumer)
{
	int ret;
	char tmp_path[PATH_MAX];
	const char *pathname;
	struct ltt_ust_stream *stream, *tmp;

	assert(sock);

	DBG("Sending streams of channel %s to UST consumer", uchan->name);

	ret = send_channel(sock, uchan);
	if (ret < 0) {
		goto error;
	}

	/* Get the right path name destination */
	if (consumer->type == CONSUMER_DST_LOCAL) {
		/* Set application path to the destination path */
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s/%s",
				consumer->dst.trace_path, consumer->subdir, usess->path);
		if (ret < 0) {
			PERROR("snprintf stream path");
			goto error;
		}
		pathname = tmp_path;
		DBG3("UST local consumer tracefile path: %s", pathname);
	} else {
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
				consumer->subdir, usess->path);
		if (ret < 0) {
			PERROR("snprintf stream path");
			goto error;
		}
		pathname = tmp_path;
		DBG3("UST network consumer subdir path: %s", pathname);
	}

	cds_list_for_each_entry_safe(stream, tmp, &uchan->streams.head, list) {
		if (!stream->obj->shm_fd) {
			continue;
		}

		ret = send_channel_stream(sock, uchan, usess, stream, consumer,
				pathname);
		if (ret < 0) {
			goto error;
		}
	}

	DBG("UST consumer channel streams sent");

	return 0;

error:
	return ret;
}

/*
 * Sending metadata to the consumer with command ADD_CHANNEL and ADD_STREAM.
 */
static int send_metadata(struct consumer_socket *sock,
		struct ust_app_session *usess, struct consumer_output *consumer)
{
	int ret, fd, fds[2];
	char tmp_path[PATH_MAX];
	const char *pathname;
	struct lttcomm_consumer_msg msg;

	/* Safety net */
	assert(usess);
	assert(consumer);
	assert(sock);

	if (sock->fd < 0) {
		ERR("Consumer socket is negative (%d)", sock->fd);
		return -EINVAL;
	}

	if (usess->metadata->obj->shm_fd == 0) {
		ERR("Metadata obj shm_fd is 0");
		ret = -1;
		goto error;
	}

	DBG("UST consumer sending metadata stream fd");

	consumer_init_channel_comm_msg(&msg,
			LTTNG_CONSUMER_ADD_CHANNEL,
			usess->metadata->obj->shm_fd,
			usess->metadata->attr.subbuf_size,
			usess->metadata->obj->memory_map_size,
			"metadata",
			1);

	ret = consumer_send_channel(sock, &msg);
	if (ret < 0) {
		goto error;
	}

	/* Sending metadata shared memory fd */
	fd = usess->metadata->obj->shm_fd;
	ret = consumer_send_fds(sock, &fd, 1);
	if (ret < 0) {
		goto error;
	}

	/* Get correct path name destination */
	if (consumer->type == CONSUMER_DST_LOCAL) {
		/* Set application path to the destination path */
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s/%s",
				consumer->dst.trace_path, consumer->subdir, usess->path);
		if (ret < 0) {
			PERROR("snprintf stream path");
			goto error;
		}
		pathname = tmp_path;

		/* Create directory */
		ret = run_as_mkdir_recursive(pathname, S_IRWXU | S_IRWXG,
				usess->uid, usess->gid);
		if (ret < 0) {
			if (ret != -EEXIST) {
				ERR("Trace directory creation error");
				goto error;
			}
		}
	} else {
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
				consumer->subdir, usess->path);
		if (ret < 0) {
			PERROR("snprintf metadata path");
			goto error;
		}
		pathname = tmp_path;
	}

	consumer_init_stream_comm_msg(&msg,
			LTTNG_CONSUMER_ADD_STREAM,
			usess->metadata->obj->shm_fd,
			usess->metadata->stream_obj->shm_fd,
			LTTNG_CONSUMER_ACTIVE_STREAM,
			DEFAULT_UST_CHANNEL_OUTPUT,
			usess->metadata->stream_obj->memory_map_size,
			usess->uid,
			usess->gid,
			consumer->net_seq_index,
			1, /* Flag metadata set */
			"metadata",
			pathname,
			usess->id);

	/* Send stream and file descriptor */
	fds[0] = usess->metadata->stream_obj->shm_fd;
	fds[1] = usess->metadata->stream_obj->wait_fd;
	ret = consumer_send_stream(sock, consumer, &msg, fds, 2);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send all stream fds of the UST session to the consumer.
 */
int ust_consumer_send_session(struct ust_app_session *usess,
		struct consumer_output *consumer, struct consumer_socket *sock)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app_channel *ua_chan;

	assert(usess);

	if (consumer == NULL || sock == NULL) {
		/* There is no consumer so just ignoring the command. */
		DBG("UST consumer does not exist. Not sending streams");
		return 0;
	}

	DBG("Sending metadata stream fd to consumer on %d", sock->fd);

	pthread_mutex_lock(sock->lock);

	/* Sending metadata information to the consumer */
	ret = send_metadata(sock, usess, consumer);
	if (ret < 0) {
		goto error;
	}

	/* Send each channel fd streams of session */
	rcu_read_lock();
	cds_lfht_for_each_entry(usess->channels->ht, &iter.iter, ua_chan,
			node.node) {
		/*
		 * Indicate that the channel was not created on the tracer side so skip
		 * sending unexisting streams.
		 */
		if (ua_chan->obj == NULL) {
			continue;
		}

		ret = send_channel_streams(sock, ua_chan, usess, consumer);
		if (ret < 0) {
			rcu_read_unlock();
			goto error;
		}
	}
	rcu_read_unlock();

	DBG("consumer fds (metadata and channel streams) sent");

	/* All good! */
	ret = 0;

error:
	pthread_mutex_unlock(sock->lock);
	return ret;
}
