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
#include <common/sessiond-comm/sessiond-comm.h>

#include "kernel-consumer.h"

/*
 * Send all stream fds of kernel channel to the consumer.
 */
int kernel_consumer_send_channel_stream(struct consumer_data *consumer_data,
		int sock, struct ltt_kernel_channel *channel, uid_t uid, gid_t gid)
{
	int ret, count = 0;
	struct ltt_kernel_stream *stream;
	struct lttcomm_consumer_msg lkm;

	DBG("Sending streams of channel %s to kernel consumer",
			channel->channel->name);

	/* Send channel */
	lkm.cmd_type = LTTNG_CONSUMER_ADD_CHANNEL;
	lkm.u.channel.channel_key = channel->fd;
	lkm.u.channel.max_sb_size = channel->channel->attr.subbuf_size;
	lkm.u.channel.mmap_len = 0;	/* for kernel */
	DBG("Sending channel %d to consumer", lkm.u.channel.channel_key);
	ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
	if (ret < 0) {
		PERROR("send consumer channel");
		goto error;
	}

	/* Send streams */
	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		if (!stream->fd) {
			continue;
		}
		/* Reset consumer message structure */
		memset(&lkm, 0, sizeof(lkm));
		lkm.cmd_type = LTTNG_CONSUMER_ADD_STREAM;
		lkm.u.stream.channel_key = channel->fd;
		lkm.u.stream.stream_key = stream->fd;
		lkm.u.stream.state = stream->state;
		lkm.u.stream.output = channel->channel->attr.output;
		lkm.u.stream.mmap_len = 0;	/* for kernel */
		lkm.u.stream.uid = uid;
		lkm.u.stream.gid = gid;
		strncpy(lkm.u.stream.path_name, stream->pathname, PATH_MAX - 1);
		lkm.u.stream.path_name[PATH_MAX - 1] = '\0';
		count++;

		DBG("Sending stream %d to consumer", lkm.u.stream.stream_key);
		ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
		if (ret < 0) {
			PERROR("send consumer stream");
			goto error;
		}
		ret = lttcomm_send_fds_unix_sock(sock, &stream->fd, 1);
		if (ret < 0) {
			PERROR("send consumer stream ancillary data");
			goto error;
		}
	}

	DBG("consumer channel streams sent");

	return 0;

error:
	return ret;
}

/*
 * Send all stream fds of the kernel session to the consumer.
 */
int kernel_consumer_send_session(struct consumer_data *consumer_data,
		struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_channel *chan;
	struct lttcomm_consumer_msg lkm;
	int sock = session->consumer_fd;

	DBG("Sending metadata stream fd");

	/* Extra protection. It's NOT supposed to be set to -1 at this point */
	if (session->consumer_fd < 0) {
		session->consumer_fd = consumer_data->cmd_sock;
	}

	if (session->metadata_stream_fd >= 0) {
		/* Send metadata channel fd */
		lkm.cmd_type = LTTNG_CONSUMER_ADD_CHANNEL;
		lkm.u.channel.channel_key = session->metadata->fd;
		lkm.u.channel.max_sb_size = session->metadata->conf->attr.subbuf_size;
		lkm.u.channel.mmap_len = 0;	/* for kernel */
		DBG("Sending metadata channel %d to consumer", lkm.u.channel.channel_key);
		ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
		if (ret < 0) {
			PERROR("send consumer channel");
			goto error;
		}

		/* Send metadata stream fd */
		lkm.cmd_type = LTTNG_CONSUMER_ADD_STREAM;
		lkm.u.stream.channel_key = session->metadata->fd;
		lkm.u.stream.stream_key = session->metadata_stream_fd;
		lkm.u.stream.state = LTTNG_CONSUMER_ACTIVE_STREAM;
		lkm.u.stream.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		lkm.u.stream.mmap_len = 0;	/* for kernel */
		lkm.u.stream.uid = session->uid;
		lkm.u.stream.gid = session->gid;
		strncpy(lkm.u.stream.path_name, session->metadata->pathname,
				PATH_MAX - 1);
		lkm.u.stream.path_name[PATH_MAX - 1] = '\0';

		DBG("Sending metadata stream %d to consumer", lkm.u.stream.stream_key);
		ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
		if (ret < 0) {
			PERROR("send consumer stream");
			goto error;
		}
		ret = lttcomm_send_fds_unix_sock(sock, &session->metadata_stream_fd, 1);
		if (ret < 0) {
			PERROR("send consumer stream");
			goto error;
		}
	}

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		ret = kernel_consumer_send_channel_stream(consumer_data, sock, chan,
				session->uid, session->gid);
		if (ret < 0) {
			goto error;
		}
	}

	DBG("consumer fds (metadata and channel streams) sent");

	return 0;

error:
	return ret;
}

