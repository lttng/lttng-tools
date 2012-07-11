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

#include <common/common.h>
#include <common/defaults.h>
#include <common/sessiond-comm/relayd.h>

#include "relayd.h"

/*
 * Send command. Fill up the header and append the data.
 */
static int send_command(struct lttcomm_sock *sock,
		enum lttcomm_sessiond_command cmd, void *data, size_t size,
		int flags)
{
	int ret;
	struct lttcomm_relayd_hdr header;
	char *buf;
	uint64_t buf_size = sizeof(header);

	if (data) {
		buf_size += size;
	}

	buf = zmalloc(buf_size);
	if (buf == NULL) {
		PERROR("zmalloc relayd send command buf");
		ret = -1;
		goto alloc_error;
	}

	header.cmd = htobe32(cmd);
	header.data_size = htobe64(size);

	/* Zeroed for now since not used. */
	header.cmd_version = 0;
	header.circuit_id = 0;

	/* Prepare buffer to send. */
	memcpy(buf, &header, sizeof(header));
	if (data) {
		memcpy(buf + sizeof(header), data, size);
	}

	ret = sock->ops->sendmsg(sock, buf, buf_size, flags);
	if (ret < 0) {
		goto error;
	}

	DBG3("Relayd sending command %d", cmd);

error:
	free(buf);
alloc_error:
	return ret;
}

/*
 * Receive reply data on socket. This MUST be call after send_command or else
 * could result in unexpected behavior(s).
 */
static int recv_reply(struct lttcomm_sock *sock, void *data, size_t size)
{
	int ret;

	DBG3("Relayd waiting for reply...");

	ret = sock->ops->recvmsg(sock, data, size, 0);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

#if 0
/*
 * Create session on the relayd.
 *
 * On error, return ret_code negative value else return 0.
 */
int relayd_create_session(struct lttcomm_sock *sock, const char *hostname,
		const char *session_name)
{
	int ret;
	struct lttcomm_relayd_create_session msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(sock);
	assert(hostname);
	assert(session_name);

	DBG("Relayd creating session for hostname %s and session name %s",
			hostname, session_name);

	strncpy(msg.hostname, hostname, sizeof(msg.hostname));
	strncpy(msg.session_name, session_name, sizeof(msg.session_name));

	/* Send command */
	ret = send_command(sock, RELAYD_CREATE_SESSION, (void *) &msg,
			sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTCOMM_OK) {
		ret = -reply.ret_code;
	} else {
		/* Success */
		ret = 0;
	}

	DBG2("Relayd created session for %s", session_name);

error:
	return ret;
}
#endif

/*
 * Add stream on the relayd and assign stream handle to the stream_id argument.
 *
 * On success return 0 else return ret_code negative value.
 */
int relayd_add_stream(struct lttcomm_sock *sock, const char *channel_name,
		const char *pathname, uint64_t *stream_id)
{
	int ret;
	struct lttcomm_relayd_add_stream msg;
	struct lttcomm_relayd_status_stream reply;

	/* Code flow error. Safety net. */
	assert(sock);
	assert(channel_name);
	assert(pathname);

	DBG("Relayd adding stream for channel name %s", channel_name);

	strncpy(msg.channel_name, channel_name, sizeof(msg.channel_name));
	strncpy(msg.pathname, pathname, sizeof(msg.pathname));

	/* Send command */
	ret = send_command(sock, RELAYD_ADD_STREAM, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	/* Back to host bytes order. */
	reply.handle = be64toh(reply.handle);
	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTCOMM_OK) {
		ret = -reply.ret_code;
		ERR("Relayd add stream replied error %d", ret);
	} else {
		/* Success */
		ret = 0;
		*stream_id = reply.handle;
	}

	DBG("Relayd stream added successfully with handle %zu", reply.handle);

error:
	return ret;
}

/*
 * Check version numbers on the relayd.
 *
 * Return 0 if compatible else negative value.
 */
int relayd_version_check(struct lttcomm_sock *sock, uint32_t major,
		uint32_t minor)
{
	int ret;
	struct lttcomm_relayd_version reply;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd version check for major.minor %u.%u", major, minor);

	/* Send command */
	ret = send_command(sock, RELAYD_VERSION, NULL, 0, 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	/* Set back to host bytes order */
	reply.major = be32toh(reply.major);
	reply.minor = be32toh(reply.minor);

	/* Validate version */
	if (reply.major <= major) {
		if (reply.minor <= minor) {
			/* Compatible */
			ret = 0;
			DBG2("Relayd version is compatible");
			goto error;
		}
	}

	/* Version number not compatible */
	DBG2("Relayd version is NOT compatible %u.%u > %u.%u", reply.major,
			reply.minor, major, minor);
	ret = -1;

error:
	return ret;
}

#if 0
/*
 * Start data command on the relayd.
 *
 * On success return 0 else return ret_code negative value.
 */
int relayd_start_data(struct lttcomm_sock *sock)
{
	int ret;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd start data command");

	/* Send command */
	ret = send_command(sock, RELAYD_START_DATA, NULL, 0, 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTCOMM_OK) {
		ret = -reply.ret_code;
	} else {
		/* Success */
		ret = 0;
	}

error:
	return ret;
}
#endif

/*
 * Add stream on the relayd and assign stream handle to the stream_id argument.
 *
 * On success return 0 else return ret_code negative value.
 */
int relayd_send_metadata(struct lttcomm_sock *sock, size_t len)
{
	int ret;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd sending metadata of size %lu", len);

	/* Send command */
	ret = send_command(sock, RELAYD_SEND_METADATA, NULL, len, 0);
	if (ret < 0) {
		goto error;
	}

	DBG2("Relayd metadata added successfully");

	/*
	 * After that call, the metadata data MUST be sent to the relayd so the
	 * receive size on the other end matches the len of the metadata packet
	 * header.
	 */

error:
	return ret;
}

/*
 * Connect to relay daemon with an allocated lttcomm_sock.
 */
int relayd_connect(struct lttcomm_sock *sock)
{
	/* Code flow error. Safety net. */
	assert(sock);

	DBG3("Relayd connect ...");

	return sock->ops->connect(sock);
}

/*
 * Close relayd socket with an allocated lttcomm_sock.
 */
int relayd_close(struct lttcomm_sock *sock)
{
	/* Code flow error. Safety net. */
	assert(sock);

	DBG3("Relayd closing socket %d", sock->fd);

	return sock->ops->close(sock);
}

/*
 * Send data header structure to the relayd.
 */
int relayd_send_data_hdr(struct lttcomm_sock *sock,
		struct lttcomm_relayd_data_hdr *hdr, size_t size)
{
	int ret;

	/* Code flow error. Safety net. */
	assert(sock);
	assert(hdr);

	DBG3("Relayd sending data header...");

	/* Again, safety net */
	if (size == 0) {
		size = sizeof(struct lttcomm_relayd_data_hdr);
	}

	/* Only send data header. */
	ret = sock->ops->sendmsg(sock, hdr, size, 0);
	if (ret < 0) {
		goto error;
	}

	/*
	 * The data MUST be sent right after that command for the receive on the
	 * other end to match the size in the header.
	 */

error:
	return ret;
}
