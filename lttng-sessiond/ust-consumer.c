/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lttngerr.h>
#include <lttng-share.h>
#include <lttng-sessiond-comm.h>
#include <lttng/lttng-consumer.h>

#include "hashtable.h"
#include "ust-consumer.h"

/*
 * Send all stream fds of UST channel to the consumer.
 */
static int send_channel_streams(int sock,
		struct ust_app_channel *uchan)
{
	int ret, fd;
	struct lttcomm_consumer_msg lum;
	struct ltt_ust_stream *stream, *tmp;

	DBG("Sending streams of channel %s to UST consumer", uchan->name);

	/* Send channel */
	lum.cmd_type = LTTNG_CONSUMER_ADD_CHANNEL;

	/*
	 * We need to keep shm_fd open while we transfer the stream file
	 * descriptors to make sure this key stays unique within the
	 * session daemon. We can free the channel shm_fd without
	 * problem after we finished sending stream fds for that
	 * channel.
	 */
	lum.u.channel.channel_key = uchan->obj->shm_fd;
	lum.u.channel.max_sb_size = uchan->attr.subbuf_size;
	lum.u.channel.mmap_len = uchan->obj->memory_map_size;
	DBG("Sending channel %d to consumer", lum.u.channel.channel_key);
	ret = lttcomm_send_unix_sock(sock, &lum, sizeof(lum));
	if (ret < 0) {
		perror("send consumer channel");
		goto error;
	}
	fd = uchan->obj->shm_fd;
	ret = lttcomm_send_fds_unix_sock(sock, &fd, 1);
	if (ret < 0) {
		perror("send consumer channel ancillary data");
		goto error;
	}

	cds_list_for_each_entry_safe(stream, tmp, &uchan->streams.head, list) {
		int fds[2];

		if (!stream->obj->shm_fd) {
			continue;
		}
		lum.cmd_type = LTTNG_CONSUMER_ADD_STREAM;
		lum.u.stream.channel_key = uchan->obj->shm_fd;
		lum.u.stream.stream_key = stream->obj->shm_fd;
		lum.u.stream.state = LTTNG_CONSUMER_ACTIVE_STREAM;
		/*
		 * FIXME Hack alert! we force MMAP for now. Mixup
		 * between EVENT and UST enums elsewhere.
		 */
		lum.u.stream.output = DEFAULT_UST_CHANNEL_OUTPUT;
		lum.u.stream.mmap_len = stream->obj->memory_map_size;
		strncpy(lum.u.stream.path_name, stream->pathname, PATH_MAX - 1);
		lum.u.stream.path_name[PATH_MAX - 1] = '\0';
		DBG("Sending stream %d to consumer", lum.u.stream.stream_key);
		ret = lttcomm_send_unix_sock(sock, &lum, sizeof(lum));
		if (ret < 0) {
			perror("send consumer stream");
			goto error;
		}

		fds[0] = stream->obj->shm_fd;
		fds[1] = stream->obj->wait_fd;
		ret = lttcomm_send_fds_unix_sock(sock, fds, 2);
		if (ret < 0) {
			perror("send consumer stream ancillary data");
			goto error;
		}
	}

	DBG("consumer channel streams sent");

	return 0;

error:
	return ret;
}

/*
 * Send all stream fds of the UST session to the consumer.
 */
int ust_consumer_send_session(int consumer_fd, struct ust_app_session *usess)
{
	int ret = 0;
	int sock = consumer_fd;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct lttcomm_consumer_msg lum;
	struct ust_app_channel *uchan;

	DBG("Sending metadata stream fd");

	if (usess->metadata->obj->shm_fd != 0) {
		int fd;
		int fds[2];

		/* Send metadata channel fd */
		lum.cmd_type = LTTNG_CONSUMER_ADD_CHANNEL;
		lum.u.channel.channel_key = usess->metadata->obj->shm_fd;
		lum.u.channel.max_sb_size = usess->metadata->attr.subbuf_size;
		lum.u.channel.mmap_len = usess->metadata->obj->memory_map_size;
		DBG("Sending metadata channel %d to consumer", lum.u.channel.channel_key);
		ret = lttcomm_send_unix_sock(sock, &lum, sizeof(lum));
		if (ret < 0) {
			perror("send consumer channel");
			goto error;
		}
		fd = usess->metadata->obj->shm_fd;
		ret = lttcomm_send_fds_unix_sock(sock, &fd, 1);
		if (ret < 0) {
			perror("send consumer metadata channel");
			goto error;
		}

		/* Send metadata stream fd */
		lum.cmd_type = LTTNG_CONSUMER_ADD_STREAM;
		lum.u.stream.channel_key = usess->metadata->obj->shm_fd;
		lum.u.stream.stream_key = usess->metadata->stream_obj->shm_fd;
		lum.u.stream.state = LTTNG_CONSUMER_ACTIVE_STREAM;
		lum.u.stream.output = DEFAULT_UST_CHANNEL_OUTPUT;
		lum.u.stream.mmap_len = usess->metadata->stream_obj->memory_map_size;
		strncpy(lum.u.stream.path_name, usess->metadata->pathname, PATH_MAX - 1);
		lum.u.stream.path_name[PATH_MAX - 1] = '\0';
		DBG("Sending metadata stream %d to consumer", lum.u.stream.stream_key);
		ret = lttcomm_send_unix_sock(sock, &lum, sizeof(lum));
		if (ret < 0) {
			perror("send consumer metadata stream");
			goto error;
		}
		fds[0] = usess->metadata->stream_obj->shm_fd;
		fds[1] = usess->metadata->stream_obj->wait_fd;
		ret = lttcomm_send_fds_unix_sock(sock, fds, 2);
		if (ret < 0) {
			perror("send consumer stream");
			goto error;
		}
	}

	/* Send each channel fd streams of session */
	rcu_read_lock();
	hashtable_get_first(usess->channels, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		uchan = caa_container_of(node, struct ust_app_channel, node);

		ret = send_channel_streams(sock, uchan);
		if (ret < 0) {
			rcu_read_unlock();
			goto error;
		}
		hashtable_get_next(usess->channels, &iter);
	}
	rcu_read_unlock();

	DBG("consumer fds (metadata and channel streams) sent");

	return 0;

error:
	return ret;
}
