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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/compat/endian.h>
#include <common/compat/string.h>
#include <common/sessiond-comm/relayd.h>
#include <common/index/ctf-index.h>
#include <common/trace-chunk.h>

#include "relayd.h"

/*
 * Send command. Fill up the header and append the data.
 */
static int send_command(struct lttcomm_relayd_sock *rsock,
		enum lttcomm_relayd_command cmd, const void *data, size_t size,
		int flags)
{
	int ret;
	struct lttcomm_relayd_hdr header;
	char *buf;
	uint64_t buf_size = sizeof(header);

	if (rsock->sock.fd < 0) {
		return -ECONNRESET;
	}

	if (data) {
		buf_size += size;
	}

	buf = zmalloc(buf_size);
	if (buf == NULL) {
		PERROR("zmalloc relayd send command buf");
		ret = -1;
		goto alloc_error;
	}

	memset(&header, 0, sizeof(header));
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

	DBG3("Relayd sending command %d of size %" PRIu64, (int) cmd, buf_size);
	ret = rsock->sock.ops->sendmsg(&rsock->sock, buf, buf_size, flags);
	if (ret < 0) {
		PERROR("Failed to send command %d of size %" PRIu64,
				(int) cmd, buf_size);
		ret = -errno;
		goto error;
	}
error:
	free(buf);
alloc_error:
	return ret;
}

/*
 * Receive reply data on socket. This MUST be call after send_command or else
 * could result in unexpected behavior(s).
 */
static int recv_reply(struct lttcomm_relayd_sock *rsock, void *data, size_t size)
{
	int ret;

	if (rsock->sock.fd < 0) {
		return -ECONNRESET;
	}

	DBG3("Relayd waiting for reply of size %zu", size);

	ret = rsock->sock.ops->recvmsg(&rsock->sock, data, size, 0);
	if (ret <= 0 || ret != size) {
		if (ret == 0) {
			/* Orderly shutdown. */
			DBG("Socket %d has performed an orderly shutdown", rsock->sock.fd);
		} else {
			DBG("Receiving reply failed on sock %d for size %zu with ret %d",
					rsock->sock.fd, size, ret);
		}
		/* Always return -1 here and the caller can use errno. */
		ret = -1;
		goto error;
	}

error:
	return ret;
}

/*
 * Starting from 2.11, RELAYD_CREATE_SESSION payload (session_name & hostname)
 * have no length restriction on the sender side.
 * Length for both payloads is stored in the msg struct. A new dynamic size
 * payload size is introduced.
 */
static int relayd_create_session_2_11(struct lttcomm_relayd_sock *rsock,
		const char *session_name, const char *hostname,
		int session_live_timer, unsigned int snapshot,
		uint64_t sessiond_session_id, const lttng_uuid sessiond_uuid)
{
	int ret;
	struct lttcomm_relayd_create_session_2_11 *msg = NULL;
	size_t session_name_len;
	size_t hostname_len;
	size_t msg_length;

	/* The two names are sent with a '\0' delimiter between them. */
	session_name_len = strlen(session_name) + 1;
	hostname_len = strlen(hostname) + 1;

	msg_length = sizeof(*msg) + session_name_len + hostname_len;
	msg = zmalloc(msg_length);
	if (!msg) {
		PERROR("zmalloc create_session_2_11 command message");
		ret = -1;
		goto error;
	}

	assert(session_name_len <= UINT32_MAX);
	msg->session_name_len = htobe32(session_name_len);

	assert(hostname_len <= UINT32_MAX);
	msg->hostname_len = htobe32(hostname_len);

	if (lttng_strncpy(msg->names, session_name, session_name_len)) {
		ret = -1;
		goto error;
	}
	if (lttng_strncpy(msg->names + session_name_len, hostname, hostname_len)) {
		ret = -1;
		goto error;
	}

	msg->live_timer = htobe32(session_live_timer);
	msg->snapshot = !!snapshot;

	lttng_uuid_copy(msg->sessiond_uuid, sessiond_uuid);
	msg->session_id = htobe64(sessiond_session_id);

	/* Send command */
	ret = send_command(rsock, RELAYD_CREATE_SESSION, msg, msg_length, 0);
	if (ret < 0) {
		goto error;
	}
error:
	free(msg);
	return ret;
}
/*
 * From 2.4 to 2.10, RELAYD_CREATE_SESSION takes additional parameters to
 * support the live reading capability.
 */
static int relayd_create_session_2_4(struct lttcomm_relayd_sock *rsock,
		const char *session_name, const char *hostname,
		int session_live_timer, unsigned int snapshot)
{
	int ret;
	struct lttcomm_relayd_create_session_2_4 msg;

	if (lttng_strncpy(msg.session_name, session_name,
			sizeof(msg.session_name))) {
		ret = -1;
		goto error;
	}
	if (lttng_strncpy(msg.hostname, hostname, sizeof(msg.hostname))) {
		ret = -1;
		goto error;
	}
	msg.live_timer = htobe32(session_live_timer);
	msg.snapshot = htobe32(snapshot);

	/* Send command */
	ret = send_command(rsock, RELAYD_CREATE_SESSION, &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * RELAYD_CREATE_SESSION from 2.1 to 2.3.
 */
static int relayd_create_session_2_1(struct lttcomm_relayd_sock *rsock)
{
	int ret;

	/* Send command */
	ret = send_command(rsock, RELAYD_CREATE_SESSION, NULL, 0, 0);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Send a RELAYD_CREATE_SESSION command to the relayd with the given socket and
 * set session_id of the relayd if we have a successful reply from the relayd.
 *
 * On success, return 0 else a negative value which is either an errno error or
 * a lttng error code from the relayd.
 */
int relayd_create_session(struct lttcomm_relayd_sock *rsock,
		uint64_t *relayd_session_id,
		const char *session_name, const char *hostname,
		int session_live_timer,
		unsigned int snapshot, uint64_t sessiond_session_id,
		const lttng_uuid sessiond_uuid)
{
	int ret;
	struct lttcomm_relayd_status_session reply;

	assert(rsock);
	assert(relayd_session_id);

	DBG("Relayd create session");

	if (rsock->minor < 4) {
		/* From 2.1 to 2.3 */
		ret = relayd_create_session_2_1(rsock);
	} else if (rsock->minor >= 4 && rsock->minor < 11) {
		/* From 2.4 to 2.10 */
		ret = relayd_create_session_2_4(rsock, session_name,
				hostname, session_live_timer, snapshot);
	} else {
		/* From 2.11 to ... */
		ret = relayd_create_session_2_11(rsock, session_name,
				hostname, session_live_timer, snapshot,
				sessiond_session_id, sessiond_uuid);
	}

	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.session_id = be64toh(reply.session_id);
	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd create session replied error %d", reply.ret_code);
		goto error;
	} else {
		ret = 0;
		*relayd_session_id = reply.session_id;
	}

	DBG("Relayd session created with id %" PRIu64, reply.session_id);

error:
	return ret;
}

static int relayd_add_stream_2_1(struct lttcomm_relayd_sock *rsock,
		const char *channel_name, const char *pathname)
{
	int ret;
	struct lttcomm_relayd_add_stream msg;

	memset(&msg, 0, sizeof(msg));
	if (lttng_strncpy(msg.channel_name, channel_name,
				sizeof(msg.channel_name))) {
		ret = -1;
		goto error;
	}

	if (lttng_strncpy(msg.pathname, pathname,
				sizeof(msg.pathname))) {
		ret = -1;
		goto error;
	}

	/* Send command */
	ret = send_command(rsock, RELAYD_ADD_STREAM, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		ret = -1;
		goto error;
	}
	ret = 0;
error:
	return ret;
}

static int relayd_add_stream_2_2(struct lttcomm_relayd_sock *rsock,
		const char *channel_name, const char *pathname,
		uint64_t tracefile_size, uint64_t tracefile_count)
{
	int ret;
	struct lttcomm_relayd_add_stream_2_2 msg;

	memset(&msg, 0, sizeof(msg));
	/* Compat with relayd 2.2 to 2.10 */
	if (lttng_strncpy(msg.channel_name, channel_name,
				sizeof(msg.channel_name))) {
		ret = -1;
		goto error;
	}
	if (lttng_strncpy(msg.pathname, pathname,
				sizeof(msg.pathname))) {
		ret = -1;
		goto error;
	}
	msg.tracefile_size = htobe64(tracefile_size);
	msg.tracefile_count = htobe64(tracefile_count);

	/* Send command */
	ret = send_command(rsock, RELAYD_ADD_STREAM, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}
	ret = 0;
error:
	return ret;
}

static int relayd_add_stream_2_11(struct lttcomm_relayd_sock *rsock,
		const char *channel_name, const char *pathname,
		uint64_t tracefile_size, uint64_t tracefile_count,
		uint64_t trace_archive_id)
{
	int ret;
	struct lttcomm_relayd_add_stream_2_11 *msg = NULL;
	size_t channel_name_len;
	size_t pathname_len;
	size_t msg_length;

	/* The two names are sent with a '\0' delimiter between them. */
	channel_name_len = strlen(channel_name) + 1;
	pathname_len = strlen(pathname) + 1;

	msg_length = sizeof(*msg) + channel_name_len + pathname_len;
	msg = zmalloc(msg_length);
	if (!msg) {
		PERROR("zmalloc add_stream_2_11 command message");
		ret = -1;
		goto error;
	}

	assert(channel_name_len <= UINT32_MAX);
	msg->channel_name_len = htobe32(channel_name_len);

	assert(pathname_len <= UINT32_MAX);
	msg->pathname_len = htobe32(pathname_len);

	if (lttng_strncpy(msg->names, channel_name, channel_name_len)) {
		ret = -1;
		goto error;
	}
	if (lttng_strncpy(msg->names + channel_name_len, pathname, pathname_len)) {
		ret = -1;
		goto error;
	}

	msg->tracefile_size = htobe64(tracefile_size);
	msg->tracefile_count = htobe64(tracefile_count);
	msg->trace_archive_id = htobe64(trace_archive_id);

	/* Send command */
	ret = send_command(rsock, RELAYD_ADD_STREAM, (void *) msg, msg_length, 0);
	if (ret < 0) {
		goto error;
	}
	ret = 0;
error:
	free(msg);
	return ret;
}

/*
 * Add stream on the relayd and assign stream handle to the stream_id argument.
 *
 * On success return 0 else return ret_code negative value.
 */
int relayd_add_stream(struct lttcomm_relayd_sock *rsock, const char *channel_name,
		const char *pathname, uint64_t *stream_id,
		uint64_t tracefile_size, uint64_t tracefile_count,
		struct lttng_trace_chunk *trace_chunk)
{
	int ret;
	struct lttcomm_relayd_status_stream reply;

	/* Code flow error. Safety net. */
	assert(rsock);
	assert(channel_name);
	assert(pathname);

	DBG("Relayd adding stream for channel name %s", channel_name);

	/* Compat with relayd 2.1 */
	if (rsock->minor == 1) {
		/* For 2.1 */
		assert(!trace_chunk);
		ret = relayd_add_stream_2_1(rsock, channel_name, pathname);
	
	} else if (rsock->minor > 1 && rsock->minor < 11) {
		/* From 2.2 to 2.10 */
		assert(!trace_chunk);
		ret = relayd_add_stream_2_2(rsock, channel_name, pathname,
				tracefile_size, tracefile_count);
	} else {
		enum lttng_trace_chunk_status chunk_status;
		uint64_t chunk_id;

		assert(trace_chunk);
		chunk_status = lttng_trace_chunk_get_id(trace_chunk,
				&chunk_id);
		assert(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);

		/* From 2.11 to ...*/
		ret = relayd_add_stream_2_11(rsock, channel_name, pathname,
				tracefile_size, tracefile_count,
				chunk_id);
	}

	if (ret) {
		ret = -1;
		goto error;
	}

	/* Waiting for reply */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	/* Back to host bytes order. */
	reply.handle = be64toh(reply.handle);
	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd add stream replied error %d", reply.ret_code);
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
 * Inform the relay that all the streams for the current channel has been sent.
 *
 * On success return 0 else return ret_code negative value.
 */
int relayd_streams_sent(struct lttcomm_relayd_sock *rsock)
{
	int ret;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd sending streams sent.");

	/* This feature was introduced in 2.4, ignore it for earlier versions. */
	if (rsock->minor < 4) {
		ret = 0;
		goto end;
	}

	/* Send command */
	ret = send_command(rsock, RELAYD_STREAMS_SENT, NULL, 0, 0);
	if (ret < 0) {
		goto error;
	}

	/* Waiting for reply */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	/* Back to host bytes order. */
	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd streams sent replied error %d", reply.ret_code);
		goto error;
	} else {
		/* Success */
		ret = 0;
	}

	DBG("Relayd streams sent success");

error:
end:
	return ret;
}

/*
 * Check version numbers on the relayd.
 * If major versions are compatible, we assign minor_to_use to the
 * minor version of the procotol we are going to use for this session.
 *
 * Return 0 if the two daemons are compatible, LTTNG_ERR_RELAYD_VERSION_FAIL
 * otherwise, or a negative value on network errors.
 */
int relayd_version_check(struct lttcomm_relayd_sock *rsock)
{
	int ret;
	struct lttcomm_relayd_version msg;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd version check for major.minor %u.%u", rsock->major,
			rsock->minor);

	memset(&msg, 0, sizeof(msg));
	/* Prepare network byte order before transmission. */
	msg.major = htobe32(rsock->major);
	msg.minor = htobe32(rsock->minor);

	/* Send command */
	ret = send_command(rsock, RELAYD_VERSION, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &msg, sizeof(msg));
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
	 */
	if (msg.major != rsock->major) {
		/* Not compatible */
		ret = LTTNG_ERR_RELAYD_VERSION_FAIL;
		DBG2("Relayd version is NOT compatible. Relayd version %u != %u (us)",
				msg.major, rsock->major);
		goto error;
	}

	/*
	 * If the relayd's minor version is higher, it will adapt to our version so
	 * we can continue to use the latest relayd communication data structure.
	 * If the received minor version is higher, the relayd should adapt to us.
	 */
	if (rsock->minor > msg.minor) {
		rsock->minor = msg.minor;
	}

	/* Version number compatible */
	DBG2("Relayd version is compatible, using protocol version %u.%u",
			rsock->major, rsock->minor);
	ret = 0;

error:
	return ret;
}

/*
 * Add stream on the relayd and assign stream handle to the stream_id argument.
 *
 * On success return 0 else return ret_code negative value.
 */
int relayd_send_metadata(struct lttcomm_relayd_sock *rsock, size_t len)
{
	int ret;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd sending metadata of size %zu", len);

	/* Send command */
	ret = send_command(rsock, RELAYD_SEND_METADATA, NULL, len, 0);
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
 * Connect to relay daemon with an allocated lttcomm_relayd_sock.
 */
int relayd_connect(struct lttcomm_relayd_sock *rsock)
{
	/* Code flow error. Safety net. */
	assert(rsock);

	if (!rsock->sock.ops) {
		/*
		 * Attempting a connect on a non-initialized socket.
		 */
		return -ECONNRESET;
	}

	DBG3("Relayd connect ...");

	return rsock->sock.ops->connect(&rsock->sock);
}

/*
 * Close relayd socket with an allocated lttcomm_relayd_sock.
 *
 * If no socket operations are found, simply return 0 meaning that everything
 * is fine. Without operations, the socket can not possibly be opened or used.
 * This is possible if the socket was allocated but not created. However, the
 * caller could simply use it to store a valid file descriptor for instance
 * passed over a Unix socket and call this to cleanup but still without a valid
 * ops pointer.
 *
 * Return the close returned value. On error, a negative value is usually
 * returned back from close(2).
 */
int relayd_close(struct lttcomm_relayd_sock *rsock)
{
	int ret;

	/* Code flow error. Safety net. */
	assert(rsock);

	/* An invalid fd is fine, return success. */
	if (rsock->sock.fd < 0) {
		ret = 0;
		goto end;
	}

	DBG3("Relayd closing socket %d", rsock->sock.fd);

	if (rsock->sock.ops) {
		ret = rsock->sock.ops->close(&rsock->sock);
	} else {
		/* Default call if no specific ops found. */
		ret = close(rsock->sock.fd);
		if (ret < 0) {
			PERROR("relayd_close default close");
		}
	}
	rsock->sock.fd = -1;

end:
	return ret;
}

/*
 * Send data header structure to the relayd.
 */
int relayd_send_data_hdr(struct lttcomm_relayd_sock *rsock,
		struct lttcomm_relayd_data_hdr *hdr, size_t size)
{
	int ret;

	/* Code flow error. Safety net. */
	assert(rsock);
	assert(hdr);

	if (rsock->sock.fd < 0) {
		return -ECONNRESET;
	}

	DBG3("Relayd sending data header of size %zu", size);

	/* Again, safety net */
	if (size == 0) {
		size = sizeof(struct lttcomm_relayd_data_hdr);
	}

	/* Only send data header. */
	ret = rsock->sock.ops->sendmsg(&rsock->sock, hdr, size, 0);
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
int relayd_send_close_stream(struct lttcomm_relayd_sock *rsock, uint64_t stream_id,
		uint64_t last_net_seq_num)
{
	int ret;
	struct lttcomm_relayd_close_stream msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd closing stream id %" PRIu64, stream_id);

	memset(&msg, 0, sizeof(msg));
	msg.stream_id = htobe64(stream_id);
	msg.last_net_seq_num = htobe64(last_net_seq_num);

	/* Send command */
	ret = send_command(rsock, RELAYD_CLOSE_STREAM, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd close stream replied error %d", reply.ret_code);
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
int relayd_data_pending(struct lttcomm_relayd_sock *rsock, uint64_t stream_id,
		uint64_t last_net_seq_num)
{
	int ret;
	struct lttcomm_relayd_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd data pending for stream id %" PRIu64, stream_id);

	memset(&msg, 0, sizeof(msg));
	msg.stream_id = htobe64(stream_id);
	msg.last_net_seq_num = htobe64(last_net_seq_num);

	/* Send command */
	ret = send_command(rsock, RELAYD_DATA_PENDING, (void *) &msg,
			sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code >= LTTNG_OK) {
		ERR("Relayd data pending replied error %d", reply.ret_code);
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
int relayd_quiescent_control(struct lttcomm_relayd_sock *rsock,
		uint64_t metadata_stream_id)
{
	int ret;
	struct lttcomm_relayd_quiescent_control msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd checking quiescent control state");

	memset(&msg, 0, sizeof(msg));
	msg.stream_id = htobe64(metadata_stream_id);

	/* Send command */
	ret = send_command(rsock, RELAYD_QUIESCENT_CONTROL, &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd quiescent control replied error %d", reply.ret_code);
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
int relayd_begin_data_pending(struct lttcomm_relayd_sock *rsock, uint64_t id)
{
	int ret;
	struct lttcomm_relayd_begin_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd begin data pending");

	memset(&msg, 0, sizeof(msg));
	msg.session_id = htobe64(id);

	/* Send command */
	ret = send_command(rsock, RELAYD_BEGIN_DATA_PENDING, &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd begin data pending replied error %d", reply.ret_code);
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
int relayd_end_data_pending(struct lttcomm_relayd_sock *rsock, uint64_t id,
		unsigned int *is_data_inflight)
{
	int ret, recv_ret;
	struct lttcomm_relayd_end_data_pending msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd end data pending");

	memset(&msg, 0, sizeof(msg));
	msg.session_id = htobe64(id);

	/* Send command */
	ret = send_command(rsock, RELAYD_END_DATA_PENDING, &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	recv_ret = be32toh(reply.ret_code);
	if (recv_ret < 0) {
		ret = recv_ret;
		goto error;
	}

	*is_data_inflight = recv_ret;

	DBG("Relayd end data pending is data inflight: %d", recv_ret);

	return 0;

error:
	return ret;
}

/*
 * Send index to the relayd.
 */
int relayd_send_index(struct lttcomm_relayd_sock *rsock,
		struct ctf_packet_index *index, uint64_t relay_stream_id,
		uint64_t net_seq_num)
{
	int ret;
	struct lttcomm_relayd_index msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	if (rsock->minor < 4) {
		DBG("Not sending indexes before protocol 2.4");
		ret = 0;
		goto error;
	}

	DBG("Relayd sending index for stream ID %" PRIu64, relay_stream_id);

	memset(&msg, 0, sizeof(msg));
	msg.relay_stream_id = htobe64(relay_stream_id);
	msg.net_seq_num = htobe64(net_seq_num);

	/* The index is already in big endian. */
	msg.packet_size = index->packet_size;
	msg.content_size = index->content_size;
	msg.timestamp_begin = index->timestamp_begin;
	msg.timestamp_end = index->timestamp_end;
	msg.events_discarded = index->events_discarded;
	msg.stream_id = index->stream_id;

	if (rsock->minor >= 8) {
		msg.stream_instance_id = index->stream_instance_id;
		msg.packet_seq_num = index->packet_seq_num;
	}

	/* Send command */
	ret = send_command(rsock, RELAYD_SEND_INDEX, &msg,
		lttcomm_relayd_index_len(lttng_to_index_major(rsock->major,
								rsock->minor),
				lttng_to_index_minor(rsock->major, rsock->minor)),
				0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd send index replied error %d", reply.ret_code);
	} else {
		/* Success */
		ret = 0;
	}

error:
	return ret;
}

/*
 * Ask the relay to reset the metadata trace file (regeneration).
 */
int relayd_reset_metadata(struct lttcomm_relayd_sock *rsock,
		uint64_t stream_id, uint64_t version)
{
	int ret;
	struct lttcomm_relayd_reset_metadata msg;
	struct lttcomm_relayd_generic_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	/* Should have been prevented by the sessiond. */
	if (rsock->minor < 8) {
		ERR("Metadata regeneration unsupported before 2.8");
		ret = -1;
		goto error;
	}

	DBG("Relayd reset metadata stream id %" PRIu64, stream_id);

	memset(&msg, 0, sizeof(msg));
	msg.stream_id = htobe64(stream_id);
	msg.version = htobe64(version);

	/* Send command */
	ret = send_command(rsock, RELAYD_RESET_METADATA, (void *) &msg, sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd reset metadata replied error %d", reply.ret_code);
	} else {
		/* Success */
		ret = 0;
	}

	DBG("Relayd reset metadata stream id %" PRIu64 " successfully", stream_id);

error:
	return ret;
}

int relayd_rotate_stream(struct lttcomm_relayd_sock *rsock, uint64_t stream_id,
		uint64_t new_chunk_id, uint64_t seq_num)
{
	int ret;
	struct lttcomm_relayd_rotate_stream *msg = NULL;
	struct lttcomm_relayd_generic_reply reply;
	size_t len;
	int msg_len;
	/* FIXME */
	char *new_pathname = NULL;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Sending rotate stream id %" PRIu64 " command to relayd", stream_id);

	/* Account for the trailing NULL. */
	len = lttng_strnlen(new_pathname, LTTNG_PATH_MAX) + 1;
	if (len > LTTNG_PATH_MAX) {
		ERR("Path used in relayd rotate stream command exceeds the maximal allowed length");
		ret = -1;
		goto error;
	}

	msg_len = offsetof(struct lttcomm_relayd_rotate_stream, new_pathname) + len;
	msg = zmalloc(msg_len);
	if (!msg) {
		PERROR("Failed to allocate relayd rotate stream command of %d bytes",
				msg_len);
		ret = -1;
		goto error;
	}

	if (lttng_strncpy(msg->new_pathname, new_pathname, len)) {
		ret = -1;
		ERR("Failed to copy relayd rotate stream command's new path name");
		goto error;
	}

	msg->pathname_length = htobe32(len);
	msg->stream_id = htobe64(stream_id);
	msg->new_chunk_id = htobe64(new_chunk_id);
	/*
	 * The seq_num is invalid for metadata streams, but it is ignored on
	 * the relay.
	 */
	msg->rotate_at_seq_num = htobe64(seq_num);

	/* Send command. */
	ret = send_command(rsock, RELAYD_ROTATE_STREAM, (void *) msg, msg_len, 0);
	if (ret < 0) {
		ERR("Send rotate command");
		goto error;
	}

	/* Receive response. */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		ERR("Receive rotate reply");
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd rotate stream replied error %d", reply.ret_code);
	} else {
		/* Success. */
		ret = 0;
		DBG("Relayd rotated stream id %" PRIu64 " successfully", stream_id);
	}

error:
	free(msg);
	return ret;
}

int relayd_rotate_rename(struct lttcomm_relayd_sock *rsock,
		const char *old_path, const char *new_path)
{
	int ret;
	struct lttcomm_relayd_rotate_rename *msg = NULL;
	struct lttcomm_relayd_generic_reply reply;
	size_t old_path_length, new_path_length;
	size_t msg_length;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd rename chunk %s to %s", old_path, new_path);

	/* The two paths are sent with a '\0' delimiter between them. */
	old_path_length = strlen(old_path) + 1;
	new_path_length = strlen(new_path) + 1;

	msg_length = sizeof(*msg) + old_path_length + new_path_length;
	msg = zmalloc(msg_length);
	if (!msg) {
		PERROR("zmalloc rotate-rename command message");
		ret = -1;
		goto error;
	}

	assert(old_path_length <= UINT32_MAX);
	msg->old_path_length = htobe32(old_path_length);

	assert(new_path_length <= UINT32_MAX);
	msg->new_path_length = htobe32(new_path_length);

	strcpy(msg->paths, old_path);
	strcpy(msg->paths + old_path_length, new_path);

	/* Send command */
	ret = send_command(rsock, RELAYD_ROTATE_RENAME, (const void *) msg,
			msg_length, 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd rotate rename replied error %d", reply.ret_code);
	} else {
		/* Success */
		ret = 0;
	}

	DBG("Relayd rotate rename completed successfully");

error:
	free(msg);
	return ret;
}

int relayd_rotate_pending(struct lttcomm_relayd_sock *rsock, uint64_t chunk_id)
{
	int ret;
	struct lttcomm_relayd_rotate_pending msg;
	struct lttcomm_relayd_rotate_pending_reply reply;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Querying relayd for rotate pending with chunk_id %" PRIu64,
			chunk_id);

	memset(&msg, 0, sizeof(msg));
	msg.chunk_id = htobe64(chunk_id);

	/* Send command */
	ret = send_command(rsock, RELAYD_ROTATE_PENDING, (void *) &msg,
			sizeof(msg), 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.generic.ret_code = be32toh(reply.generic.ret_code);

	/* Return session id or negative ret code. */
	if (reply.generic.ret_code != LTTNG_OK) {
		ret = -reply.generic.ret_code;
		ERR("Relayd rotate pending replied with error %d", ret);
		goto error;
	} else {
		/* No error, just rotate pending state */
		if (reply.is_pending == 0 || reply.is_pending == 1) {
			ret = reply.is_pending;
			DBG("Relayd rotate pending command completed successfully with result \"%s\"",
					ret ? "rotation pending" : "rotation NOT pending");
		} else {
			ret = -LTTNG_ERR_UNK;
		}
	}

error:
	return ret;
}

int relayd_mkdir(struct lttcomm_relayd_sock *rsock, const char *path)
{
	int ret;
	struct lttcomm_relayd_mkdir *msg;
	struct lttcomm_relayd_generic_reply reply;
	size_t len;

	/* Code flow error. Safety net. */
	assert(rsock);

	DBG("Relayd mkdir path %s", path);

	len = strlen(path) + 1;
	msg = zmalloc(sizeof(msg->length) + len);
	if (!msg) {
		PERROR("Alloc mkdir msg");
		ret = -1;
		goto error;
	}
	msg->length = htobe32((uint32_t) len);

	if (lttng_strncpy(msg->path, path, len)) {
		ret = -1;
		goto error;
	}

	/* Send command */
	ret = send_command(rsock, RELAYD_MKDIR, (void *) msg,
			sizeof(msg->length) + len, 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, (void *) &reply, sizeof(reply));
	if (ret < 0) {
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);

	/* Return session id or negative ret code. */
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd mkdir replied error %d", reply.ret_code);
	} else {
		/* Success */
		ret = 0;
	}

	DBG("Relayd mkdir completed successfully");

error:
	free(msg);
	return ret;
}
