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
#include <inttypes.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/sessiond-comm/relayd.h>

#include "relayd.h"

/*
 * Send command. Fill up the header and append the data.
 */
static int send_command(struct lttcomm_sock *sock,
		enum lttcomm_relayd_command cmd, void *data, size_t size,
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
		ret = -errno;
		goto error;
	}

	DBG3("Relayd sending command %d of size %" PRIu64, cmd, buf_size);

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

	DBG3("Relayd waiting for reply of size %ld", size);

	ret = sock->ops->recvmsg(sock, data, size, 0);
	if (ret < 0) {
		ret = -errno;
		goto error;
	}

error:
	return ret;
}

/*
 * Send a RELAYD_CREATE_SESSION command to the relayd with the given socket and
 * set session_id of the relayd if we have a successful reply from the relayd.
 *
 * On success, return 0 else a negative value being a lttng_error_code returned
 * from the relayd.
 */
int relayd_create_session(struct lttcomm_sock *sock, uint64_t *session_id)
{
	int ret;
	struct lttcomm_relayd_status_session reply;

	assert(sock);
	assert(session_id);

	DBG("Relayd create session");

	/* Send command */
	ret = send_command(sock, RELAYD_CREATE_SESSION, NULL, 0, 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.session_id = be64toh(reply.session_id);
	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -reply.ret_code;
		ERR("Relayd create session replied error %d", ret);
		goto error;
	} else {
		ret = 0;
		*session_id = reply.session_id;
	}

	DBG("Relayd session created with id %" PRIu64, reply.session_id);

error:
	return ret;
}

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

	/* Waiting for reply */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	/* Back to host bytes order. */
	reply.handle = be64toh(reply.handle);
	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -reply.ret_code;
		ERR("Relayd add stream replied error %d", ret);
	} else {
		/* Success */
		ret = 0;
		*stream_id = reply.handle;
	}

	DBG("Relayd stream added successfully with handle %" PRIu64,
		reply.handle);

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
	struct lttcomm_relayd_version msg;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd version check for major.minor %u.%u", major, minor);

	/* Prepare network byte order before transmission. */
	msg.major = htobe32(major);
	msg.minor = htobe32(minor);

	/* Send command */
	ret = send_command(sock, RELAYD_VERSION, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &msg, sizeof(msg));
	if (ret < 0) {
		goto error;
	}

	/* Set back to host bytes order */
	msg.major = be32toh(msg.major);
	msg.minor = be32toh(msg.minor);

	/*
	 * Only validate the major version. If the other side is higher,
	 * communication is not possible. Only major version equal can talk to each
	 * other. If the minor version differs, the lowest version is used by both
	 * sides.
	 *
	 * For now, before 2.1.0 stable release, we don't have to check the minor
	 * because this new mechanism with the relayd will only be available with
	 * 2.1 and NOT 2.0.x.
	 */
	if (msg.major == major) {
		/* Compatible */
		ret = 0;
		DBG2("Relayd version is compatible");
		goto error;
	}

	/*
	 * After 2.1.0 release, for the 2.2 release, at this point will have to
	 * check the minor version in order for the session daemon to know which
	 * structure to use to communicate with the relayd. If the relayd's minor
	 * version is higher, it will adapt to our version so we can continue to
	 * use the latest relayd communication data structure.
	 */

	/* Version number not compatible */
	DBG2("Relayd version is NOT compatible. Relayd version %u != %u (us)",
			msg.major, major);
	ret = -1;

error:
	return ret;
}

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

	DBG("Relayd sending metadata of size %zu", len);

	/* Send command */
	ret = send_command(sock, RELAYD_SEND_METADATA, NULL, len, 0);
	if (ret < 0) {
		goto error;
	}

	DBG2("Relayd metadata added successfully");

	/*
	 * After that call, the metadata data MUST be sent to the relayd so the
	 * receive size on the other end matches the len of the metadata packet
	 * header. This is why we don't wait for a reply here.
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

	DBG3("Relayd sending data header of size %ld", size);

	/* Again, safety net */
	if (size == 0) {
		size = sizeof(struct lttcomm_relayd_data_hdr);
	}

	/* Only send data header. */
	ret = sock->ops->sendmsg(sock, hdr, size, 0);
	if (ret < 0) {
		ret = -errno;
		goto error;
	}

	/*
	 * The data MUST be sent right after that command for the receive on the
	 * other end to match the size in the header.
	 */

error:
	return ret;
}

/*
 * Send close stream command to the relayd.
 */
int relayd_send_close_stream(struct lttcomm_sock *sock, uint64_t stream_id,
		uint64_t last_net_seq_num)
{
	int ret;
	struct lttcomm_relayd_close_stream msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd closing stream id %" PRIu64, stream_id);

	msg.stream_id = htobe64(stream_id);
	msg.last_net_seq_num = htobe64(last_net_seq_num);

	/* Send command */
	ret = send_command(sock, RELAYD_CLOSE_STREAM, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -reply.ret_code;
		ERR("Relayd close stream replied error %d", ret);
	} else {
		/* Success */
		ret = 0;
	}

	DBG("Relayd close stream id %" PRIu64 " successfully", stream_id);

error:
	return ret;
}

/*
 * Check for data availability for a given stream id.
 *
 * Return 0 if NOT pending, 1 if so and a negative value on error.
 */
int relayd_data_pending(struct lttcomm_sock *sock, uint64_t stream_id,
		uint64_t last_net_seq_num)
{
	int ret;
	struct lttcomm_relayd_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd data pending for stream id %" PRIu64, stream_id);

	msg.stream_id = htobe64(stream_id);
	msg.last_net_seq_num = htobe64(last_net_seq_num);

	/* Send command */
	ret = send_command(sock, RELAYD_DATA_PENDING, (void *) &msg,
			sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code >= LTTNG_OK) {
		ret = -reply.ret_code;
		ERR("Relayd data pending replied error %d", ret);
	}

	/* At this point, the ret code is either 1 or 0 */
	ret = reply.ret_code;

	DBG("Relayd data is %s pending for stream id %" PRIu64,
			ret == 1 ? "" : "NOT", stream_id);

error:
	return ret;
}

/*
 * Check on the relayd side for a quiescent state on the control socket.
 */
int relayd_quiescent_control(struct lttcomm_sock *sock,
		uint64_t metadata_stream_id)
{
	int ret;
	struct lttcomm_relayd_quiescent_control msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd checking quiescent control state");

	msg.stream_id = htobe64(metadata_stream_id);

	/* Send command */
	ret = send_command(sock, RELAYD_QUIESCENT_CONTROL, &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -reply.ret_code;
		ERR("Relayd quiescent control replied error %d", ret);
		goto error;
	}

	/* Control socket is quiescent */
	return 0;

error:
	return ret;
}

/*
 * Begin a data pending command for a specific session id.
 */
int relayd_begin_data_pending(struct lttcomm_sock *sock, uint64_t id)
{
	int ret;
	struct lttcomm_relayd_begin_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd begin data pending");

	msg.session_id = htobe64(id);

	/* Send command */
	ret = send_command(sock, RELAYD_BEGIN_DATA_PENDING, &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -reply.ret_code;
		ERR("Relayd begin data pending replied error %d", ret);
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * End a data pending command for a specific session id.
 *
 * Return 0 on success and set is_data_inflight to 0 if no data is being
 * streamed or 1 if it is the case.
 */
int relayd_end_data_pending(struct lttcomm_sock *sock, uint64_t id,
		unsigned int *is_data_inflight)
{
	int ret;
	struct lttcomm_relayd_end_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(sock);

	DBG("Relayd end data pending");

	msg.session_id = htobe64(id);

	/* Send command */
	ret = send_command(sock, RELAYD_END_DATA_PENDING, &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Recevie response */
	ret = recv_reply(sock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);
	if (reply.ret_code < 0) {
		ret = reply.ret_code;
		goto error;
	}

	*is_data_inflight = reply.ret_code;

	DBG("Relayd end data pending is data inflight: %d", reply.ret_code);

	return 0;

error:
	return ret;
}
