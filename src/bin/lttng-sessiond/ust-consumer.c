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
 * Send all stream fds of UST channel to the consumer.
 */
static int send_channel_streams(int sock,
		struct ust_app_channel *uchan, const char *path,
		uid_t uid, gid_t gid, struct consumer_output *consumer)
{
	int ret, fd;
	char tmp_path[PATH_MAX];
	const char *pathname;
	struct lttcomm_consumer_msg lum;
	struct ltt_ust_stream *stream, *tmp;

	DBG("Sending streams of channel %s to UST consumer", uchan->name);

	consumer_init_channel_comm_msg(&lum,
			LTTNG_CONSUMER_ADD_CHANNEL,
			uchan->obj->shm_fd,
			uchan->attr.subbuf_size,
			uchan->obj->memory_map_size,
			uchan->name);

	ret = consumer_send_channel(sock, &lum);
	if (ret < 0) {
		goto error;
	}

	fd = uchan->obj->shm_fd;
	ret = consumer_send_fds(sock, &fd, 1);
	if (ret < 0) {
		goto error;
	}

	/* Get the right path name destination */
	if (consumer->type == CONSUMER_DST_LOCAL) {
		/* Set application path to the destination path */
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
				consumer->dst.trace_path, path);
		if (ret < 0) {
			PERROR("snprintf stream path");
			goto error;
		}
		pathname = tmp_path;
		DBG3("UST local consumer tracefile path: %s", pathname);
	} else {
		ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
				consumer->subdir, path);
		if (ret < 0) {
			PERROR("snprintf stream path");
			goto error;
		}
		pathname = tmp_path;
		DBG3("UST network consumer subdir path: %s", pathname);
	}

	cds_list_for_each_entry_safe(stream, tmp, &uchan->streams.head, list) {
		int fds[2];

		if (!stream->obj->shm_fd) {
			continue;
		}

		consumer_init_stream_comm_msg(&lum,
				LTTNG_CONSUMER_ADD_STREAM,
				uchan->obj->shm_fd,
				stream->obj->shm_fd,
				LTTNG_CONSUMER_ACTIVE_STREAM,
				DEFAULT_UST_CHANNEL_OUTPUT,
				stream->obj->memory_map_size,
				uid,
				gid,
				consumer->net_seq_index,
				0, /* Metadata flag unset */
				stream->name,
				pathname);

		/* Send stream and file descriptor */
		fds[0] = stream->obj->shm_fd;
		fds[1] = stream->obj->wait_fd;
		ret = consumer_send_stream(sock, consumer, &lum, fds, 2);
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
 * Send all stream fds of the UST session to the consumer.
 */
int ust_consumer_send_session(int consumer_fd, struct ust_app_session *usess,
		struct consumer_output *consumer)
{
	int ret = 0;
	int sock = consumer_fd;
	char tmp_path[PATH_MAX];
	const char *pathname;
	struct lttng_ht_iter iter;
	struct lttcomm_consumer_msg lum;
	struct ust_app_channel *ua_chan;

	DBG("Sending metadata stream fd");

	if (consumer_fd < 0) {
		ERR("Consumer has negative file descriptor");
		return -EINVAL;
	}

	if (usess->metadata->obj->shm_fd != 0) {
		int fd;
		int fds[2];

		consumer_init_channel_comm_msg(&lum,
				LTTNG_CONSUMER_ADD_CHANNEL,
				usess->metadata->obj->shm_fd,
				usess->metadata->attr.subbuf_size,
				usess->metadata->obj->memory_map_size,
				"metadata");

		ret = consumer_send_channel(sock, &lum);
		if (ret < 0) {
			goto error;
		}

		fd = usess->metadata->obj->shm_fd;
		ret = consumer_send_fds(sock, &fd, 1);
		if (ret < 0) {
			goto error;
		}

		/* Get correct path name destination */
		if (consumer->type == CONSUMER_DST_LOCAL) {
			/* Set application path to the destination path */
			ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
					consumer->dst.trace_path, usess->path);
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

		consumer_init_stream_comm_msg(&lum,
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
				pathname);

		/* Send stream and file descriptor */
		fds[0] = usess->metadata->stream_obj->shm_fd;
		fds[1] = usess->metadata->stream_obj->wait_fd;
		ret = consumer_send_stream(sock, consumer, &lum, fds, 2);
		if (ret < 0) {
			goto error;
		}
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

		ret = send_channel_streams(sock, ua_chan, usess->path, usess->uid,
				usess->gid, consumer);
		if (ret < 0) {
			rcu_read_unlock();
			goto error;
		}
	}
	rcu_read_unlock();

	DBG("consumer fds (metadata and channel streams) sent");

	return 0;

error:
	return ret;
}

/*
 * Send relayd socket to consumer associated with a session name.
 *
 * On success return positive value. On error, negative value.
 */
int ust_consumer_send_relayd_socket(int consumer_sock,
		struct lttcomm_sock *sock, struct consumer_output *consumer,
		enum lttng_stream_type type)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	/* Code flow error. Safety net. */
	assert(sock);

	msg.cmd_type = LTTNG_CONSUMER_ADD_RELAYD_SOCKET;
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

	DBG("UST consumer relayd socket sent");

error:
	return ret;
}
