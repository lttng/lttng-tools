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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/uri.h>

#include "consumer.h"

/*
 * Allocate and assign data to a consumer_output object.
 *
 * Return pointer to structure.
 */
struct consumer_output *consumer_create_output(enum consumer_dst_type type)
{
	struct consumer_output *output = NULL;

	output = zmalloc(sizeof(struct consumer_output));
	if (output == NULL) {
		PERROR("zmalloc consumer_output");
		goto error;
	}

	/* By default, consumer output is enabled */
	output->enabled = 1;
	output->type = type;
	output->net_seq_index = -1;
	/*
	 * Important to keep it to a negative value on creation since it was zeroed
	 * during allocation and the file descriptor 0 is a valid one.
	 */
	output->sock = -1;

error:
	return output;
}

/*
 * Delete the consumer_output object from the list and free the ptr.
 */
void consumer_destroy_output(struct consumer_output *obj)
{
	if (obj == NULL) {
		return;
	}

	if (obj->sock >= 0) {
		(void) close(obj->sock);
	}
	free(obj);
}

/*
 * Copy consumer output and returned the newly allocated copy.
 */
struct consumer_output *consumer_copy_output(struct consumer_output *obj)
{
	struct consumer_output *output;

	assert(obj);

	output = consumer_create_output(obj->type);
	if (output == NULL) {
		goto error;
	}

	memcpy(output, obj, sizeof(struct consumer_output));

error:
	return output;
}

/*
 * Set network URI to the consumer output object.
 *
 * Return 0 on success. Negative value on error.
 */
int consumer_set_network_uri(struct consumer_output *obj,
		struct lttng_uri *uri)
{
	int ret;
	char tmp_path[PATH_MAX];
	char hostname[HOST_NAME_MAX];
	struct lttng_uri *dst_uri = NULL;

	/* Code flow error safety net. */
	assert(obj);
	assert(uri);

	switch (uri->stype) {
	case LTTNG_STREAM_CONTROL:
		dst_uri = &obj->dst.net.control;
		obj->dst.net.control_isset = 1;
		if (uri->port == 0) {
			/* Assign default port. */
			uri->port = DEFAULT_NETWORK_CONTROL_PORT;
		}
		break;
	case LTTNG_STREAM_DATA:
		dst_uri = &obj->dst.net.data;
		obj->dst.net.data_isset = 1;
		if (uri->port == 0) {
			/* Assign default port. */
			uri->port = DEFAULT_NETWORK_DATA_PORT;
		}
		break;
	default:
		ERR("Set network uri type unknown %d", uri->stype);
		goto error;
	}

	ret = uri_compare(dst_uri, uri);
	if (!ret) {
		/* Same URI, don't touch it and return success. */
		DBG3("URI network compare are the same");
		goto end;
	}

	/* URIs were not equal, replacing it. */
	memset(dst_uri, 0, sizeof(struct lttng_uri));
	memcpy(dst_uri, uri, sizeof(struct lttng_uri));
	obj->type = CONSUMER_DST_NET;

	/* Handle subdir and add hostname in front. */
	if (dst_uri->stype == LTTNG_STREAM_CONTROL) {
		/* Get hostname to append it in the pathname */
		ret = gethostname(hostname, sizeof(hostname));
		if (ret < 0) {
			PERROR("gethostname. Fallback on default localhost");
			strncpy(hostname, "localhost", sizeof(hostname));
		}
		hostname[sizeof(hostname) - 1] = '\0';

		/* Setup consumer subdir if none present in the control URI */
		if (strlen(dst_uri->subdir) == 0) {
			ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
					hostname, obj->subdir);
		} else {
			ret = snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
					hostname, dst_uri->subdir);
		}
		if (ret < 0) {
			PERROR("snprintf set consumer uri subdir");
			goto error;
		}

		strncpy(obj->subdir, tmp_path, sizeof(obj->subdir));
		DBG3("Consumer set network uri subdir path %s", tmp_path);
	}

end:
	return 0;

error:
	return -1;
}

/*
 * Send file descriptor to consumer via sock.
 */
int consumer_send_fds(int sock, int *fds, size_t nb_fd)
{
	int ret;

	assert(fds);
	assert(nb_fd > 0);

	ret = lttcomm_send_fds_unix_sock(sock, fds, nb_fd);
	if (ret < 0) {
		PERROR("send consumer fds");
		goto error;
	}

error:
	return ret;
}

/*
 * Consumer send channel communication message structure to consumer.
 */
int consumer_send_channel(int sock, struct lttcomm_consumer_msg *msg)
{
	int ret;

	assert(msg);
	assert(sock >= 0);

	ret = lttcomm_send_unix_sock(sock, msg,
			sizeof(struct lttcomm_consumer_msg));
	if (ret < 0) {
		PERROR("send consumer channel");
		goto error;
	}

error:
	return ret;
}

/*
 * Init channel communication message structure.
 */
void consumer_init_channel_comm_msg(struct lttcomm_consumer_msg *msg,
		enum lttng_consumer_command cmd,
		int channel_key,
		uint64_t max_sb_size,
		uint64_t mmap_len,
		const char *name)
{
	assert(msg);

	/* TODO: Args validation */

	/* Zeroed structure */
	memset(msg, 0, sizeof(struct lttcomm_consumer_msg));

	/* Send channel */
	msg->cmd_type = cmd;
	msg->u.channel.channel_key = channel_key;
	msg->u.channel.max_sb_size = max_sb_size;
	msg->u.channel.mmap_len = mmap_len;
}

/*
 * Init stream communication message structure.
 */
void consumer_init_stream_comm_msg(struct lttcomm_consumer_msg *msg,
		enum lttng_consumer_command cmd,
		int channel_key,
		int stream_key,
		uint32_t state,
		enum lttng_event_output output,
		uint64_t mmap_len,
		uid_t uid,
		gid_t gid,
		int net_index,
		unsigned int metadata_flag,
		const char *name,
		const char *pathname)
{
	assert(msg);

	memset(msg, 0, sizeof(struct lttcomm_consumer_msg));

	/* TODO: Args validation */

	msg->cmd_type = cmd;
	msg->u.stream.channel_key = channel_key;
	msg->u.stream.stream_key = stream_key;
	msg->u.stream.state = state;
	msg->u.stream.output = output;
	msg->u.stream.mmap_len = mmap_len;
	msg->u.stream.uid = uid;
	msg->u.stream.gid = gid;
	msg->u.stream.net_index = net_index;
	msg->u.stream.metadata_flag = metadata_flag;
	strncpy(msg->u.stream.name, name, sizeof(msg->u.stream.name));
	msg->u.stream.name[sizeof(msg->u.stream.name) - 1] = '\0';
	strncpy(msg->u.stream.path_name, pathname,
			sizeof(msg->u.stream.path_name));
	msg->u.stream.path_name[sizeof(msg->u.stream.path_name) - 1] = '\0';
}

/*
 * Send stream communication structure to the consumer.
 */
int consumer_send_stream(int sock, struct consumer_output *dst,
	struct lttcomm_consumer_msg *msg, int *fds, size_t nb_fd)
{
	int ret;

	assert(msg);
	assert(dst);

	switch (dst->type) {
	case CONSUMER_DST_NET:
		/* Consumer should send the stream on the network. */
		msg->u.stream.net_index = dst->net_seq_index;
		break;
	case CONSUMER_DST_LOCAL:
		/* Add stream file name to stream path */
		strncat(msg->u.stream.path_name, "/", sizeof(msg->u.stream.path_name));
		strncat(msg->u.stream.path_name, msg->u.stream.name,
				sizeof(msg->u.stream.path_name));
		msg->u.stream.path_name[sizeof(msg->u.stream.path_name) - 1] = '\0';
		/* Indicate that the stream is NOT network */
		msg->u.stream.net_index = -1;
		break;
	default:
		ERR("Consumer unknown output type (%d)", dst->type);
		ret = -1;
		goto error;
	}

	/* Send on socket */
	ret = lttcomm_send_unix_sock(sock, msg,
			sizeof(struct lttcomm_consumer_msg));
	if (ret < 0) {
		PERROR("send consumer stream");
		goto error;
	}

	ret = consumer_send_fds(sock, fds, nb_fd);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}
