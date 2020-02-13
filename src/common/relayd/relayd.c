/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
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
#include <common/string-utils/format.h>

#include "relayd.h"

static
bool relayd_supports_chunks(const struct lttcomm_relayd_sock *sock)
{
	if (sock->major > 2) {
		return true;
	} else if (sock->major == 2 && sock->minor >= 11) {
		return true;
	}
	return false;
}

static
bool relayd_supports_get_configuration(const struct lttcomm_relayd_sock *sock)
{
	if (sock->major > 2) {
		return true;
	} else if (sock->major == 2 && sock->minor >= 12) {
		return true;
	}
	return false;
}

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
 * Starting from 2.11, RELAYD_CREATE_SESSION payload (session_name,
 * hostname, and base_path) have no length restriction on the sender side.
 * Length for both payloads is stored in the msg struct. A new dynamic size
 * payload size is introduced.
 */
static int relayd_create_session_2_11(struct lttcomm_relayd_sock *rsock,
		const char *session_name, const char *hostname,
		const char *base_path, int session_live_timer,
		unsigned int snapshot, uint64_t sessiond_session_id,
		const lttng_uuid sessiond_uuid, const uint64_t *current_chunk_id,
		time_t creation_time, bool session_name_contains_creation_time,
		struct lttcomm_relayd_create_session_reply_2_11 *reply,
		char *output_path)
{
	int ret;
	struct lttcomm_relayd_create_session_2_11 *msg = NULL;
	size_t session_name_len;
	size_t hostname_len;
	size_t base_path_len;
	size_t msg_length;
	char *dst;

	if (!base_path) {
		base_path = "";
	}
	/* The three names are sent with a '\0' delimiter between them. */
	session_name_len = strlen(session_name) + 1;
	hostname_len = strlen(hostname) + 1;
	base_path_len = strlen(base_path) + 1;

	msg_length = sizeof(*msg) + session_name_len + hostname_len + base_path_len;
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

	assert(base_path_len <= UINT32_MAX);
	msg->base_path_len = htobe32(base_path_len);

	dst = msg->names;
	if (lttng_strncpy(dst, session_name, session_name_len)) {
		ret = -1;
		goto error;
	}
	dst += session_name_len;
	if (lttng_strncpy(dst, hostname, hostname_len)) {
		ret = -1;
		goto error;
	}
	dst += hostname_len;
	if (lttng_strncpy(dst, base_path, base_path_len)) {
		ret = -1;
		goto error;
	}

	msg->live_timer = htobe32(session_live_timer);
	msg->snapshot = !!snapshot;

	lttng_uuid_copy(msg->sessiond_uuid, sessiond_uuid);
	msg->session_id = htobe64(sessiond_session_id);
	msg->session_name_contains_creation_time = session_name_contains_creation_time;
	if (current_chunk_id) {
		LTTNG_OPTIONAL_SET(&msg->current_chunk_id,
				htobe64(*current_chunk_id));
	}

	msg->creation_time = htobe64((uint64_t) creation_time);

	/* Send command */
	ret = send_command(rsock, RELAYD_CREATE_SESSION, msg, msg_length, 0);
	if (ret < 0) {
		goto error;
	}
	/* Receive response */
	ret = recv_reply(rsock, reply, sizeof(*reply));
	if (ret < 0) {
		goto error;
	}
	reply->generic.session_id = be64toh(reply->generic.session_id);
	reply->generic.ret_code = be32toh(reply->generic.ret_code);
	reply->output_path_length = be32toh(reply->output_path_length);
	if (reply->output_path_length >= LTTNG_PATH_MAX) {
		ERR("Invalid session output path length in reply (%" PRIu32 " bytes) exceeds maximal allowed length (%d bytes)",
				reply->output_path_length, LTTNG_PATH_MAX);
		ret = -1;
		goto error;
	}
	ret = recv_reply(rsock, output_path, reply->output_path_length);
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
		int session_live_timer, unsigned int snapshot,
		struct lttcomm_relayd_status_session *reply)
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

	/* Receive response */
	ret = recv_reply(rsock, reply, sizeof(*reply));
	if (ret < 0) {
		goto error;
	}
	reply->session_id = be64toh(reply->session_id);
	reply->ret_code = be32toh(reply->ret_code);
error:
	return ret;
}

/*
 * RELAYD_CREATE_SESSION from 2.1 to 2.3.
 */
static int relayd_create_session_2_1(struct lttcomm_relayd_sock *rsock,
		struct lttcomm_relayd_status_session *reply)
{
	int ret;

	/* Send command */
	ret = send_command(rsock, RELAYD_CREATE_SESSION, NULL, 0, 0);
	if (ret < 0) {
		goto error;
	}

	/* Receive response */
	ret = recv_reply(rsock, reply, sizeof(*reply));
	if (ret < 0) {
		goto error;
	}
	reply->session_id = be64toh(reply->session_id);
	reply->ret_code = be32toh(reply->ret_code);
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
		const char *base_path, int session_live_timer,
		unsigned int snapshot, uint64_t sessiond_session_id,
		const lttng_uuid sessiond_uuid,
		const uint64_t *current_chunk_id,
		time_t creation_time, bool session_name_contains_creation_time,
		char *output_path)
{
	int ret;
	struct lttcomm_relayd_create_session_reply_2_11 reply = {};

	assert(rsock);
	assert(relayd_session_id);

	DBG("Relayd create session");

	if (rsock->minor < 4) {
		/* From 2.1 to 2.3 */
		ret = relayd_create_session_2_1(rsock, &reply.generic);
	} else if (rsock->minor >= 4 && rsock->minor < 11) {
		/* From 2.4 to 2.10 */
		ret = relayd_create_session_2_4(rsock, session_name,
				hostname, session_live_timer, snapshot,
				&reply.generic);
	} else {
		/* From 2.11 to ... */
		ret = relayd_create_session_2_11(rsock, session_name,
				hostname, base_path, session_live_timer, snapshot,
				sessiond_session_id, sessiond_uuid,
				current_chunk_id, creation_time,
				session_name_contains_creation_time,
				&reply, output_path);
	}

	if (ret < 0) {
		goto error;
	}

	/* Return session id or negative ret code. */
	if (reply.generic.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd create session replied error %d",
			reply.generic.ret_code);
		goto error;
	} else {
		ret = 0;
		*relayd_session_id = reply.generic.session_id;
	}

	DBG("Relayd session created with id %" PRIu64, reply.generic.session_id);

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
	msg->trace_chunk_id = htobe64(trace_archive_id);

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
 * Chunks are not supported by relayd prior to 2.11, but are used to
 * internally between session daemon and consumer daemon to keep track
 * of the channel and stream output path.
 *
 * On success return 0 else return ret_code negative value.
 */
int relayd_add_stream(struct lttcomm_relayd_sock *rsock, const char *channel_name,
		const char *domain_name, const char *_pathname, uint64_t *stream_id,
		uint64_t tracefile_size, uint64_t tracefile_count,
		struct lttng_trace_chunk *trace_chunk)
{
	int ret;
	struct lttcomm_relayd_status_stream reply;
	char pathname[RELAYD_COMM_LTTNG_PATH_MAX];
	const char *separator;

	/* Code flow error. Safety net. */
	assert(rsock);
	assert(channel_name);
	assert(domain_name);
	assert(_pathname);
	assert(trace_chunk);

	DBG("Relayd adding stream for channel name %s", channel_name);

	if (_pathname[0] == '\0') {
		separator = "";
	} else {
		separator = "/";
	}
	ret = snprintf(pathname, RELAYD_COMM_LTTNG_PATH_MAX, "%s%s%s",
			domain_name, separator, _pathname);
	if (ret <= 0 || ret >= RELAYD_COMM_LTTNG_PATH_MAX) {
		ERR("stream path too long.");
		ret = -1;
		goto error;
	}

	/* Compat with relayd 2.1 */
	if (rsock->minor == 1) {
		/* For 2.1 */
		ret = relayd_add_stream_2_1(rsock, channel_name, pathname);
	
	} else if (rsock->minor > 1 && rsock->minor < 11) {
		/* From 2.2 to 2.10 */
		ret = relayd_add_stream_2_2(rsock, channel_name, pathname,
				tracefile_size, tracefile_count);
	} else {
		enum lttng_trace_chunk_status chunk_status;
		uint64_t chunk_id;

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

int relayd_rotate_streams(struct lttcomm_relayd_sock *sock,
		unsigned int stream_count, const uint64_t *new_chunk_id,
		const struct relayd_stream_rotation_position *positions)
{
	int ret;
	unsigned int i;
	struct lttng_dynamic_buffer payload;
	struct lttcomm_relayd_generic_reply reply = {};
	const struct lttcomm_relayd_rotate_streams msg = {
		.stream_count = htobe32((uint32_t) stream_count),
		.new_chunk_id = (typeof(msg.new_chunk_id)) {
			.is_set = !!new_chunk_id,
			.value = htobe64(new_chunk_id ? *new_chunk_id : 0),
		},
	};
	char new_chunk_id_buf[MAX_INT_DEC_LEN(*new_chunk_id)] = {};
	const char *new_chunk_id_str;

	if (!relayd_supports_chunks(sock)) {
		DBG("Refusing to rotate remote streams: relayd does not support chunks");
		return 0;
	}

	lttng_dynamic_buffer_init(&payload);

	/* Code flow error. Safety net. */
	assert(sock);

	if (new_chunk_id) {
		ret = snprintf(new_chunk_id_buf, sizeof(new_chunk_id_buf),
				"%" PRIu64, *new_chunk_id);
		if (ret == -1 || ret >= sizeof(new_chunk_id_buf)) {
			new_chunk_id_str = "formatting error";
		} else {
			new_chunk_id_str = new_chunk_id_buf;
		}
	} else {
		new_chunk_id_str = "none";
	}

	DBG("Preparing \"rotate streams\" command payload: new_chunk_id = %s, stream_count = %u",
			new_chunk_id_str, stream_count);

	ret = lttng_dynamic_buffer_append(&payload, &msg, sizeof(msg));
	if (ret) {
		ERR("Failed to allocate \"rotate streams\" command payload");
		goto error;
	}

	for (i = 0; i < stream_count; i++) {
		const struct relayd_stream_rotation_position *position =
				&positions[i];
		const struct lttcomm_relayd_stream_rotation_position comm_position = {
			.stream_id = htobe64(position->stream_id),
			.rotate_at_seq_num = htobe64(
					position->rotate_at_seq_num),
		};

		DBG("Rotate stream %" PRIu64 "at sequence number %" PRIu64,
				position->stream_id,
				position->rotate_at_seq_num);
		ret = lttng_dynamic_buffer_append(&payload, &comm_position,
				sizeof(comm_position));
		if (ret) {
			ERR("Failed to allocate \"rotate streams\" command payload");
			goto error;
		}
	}

	/* Send command. */
	ret = send_command(sock, RELAYD_ROTATE_STREAMS, payload.data,
			payload.size, 0);
	if (ret < 0) {
		ERR("Failed to send \"rotate stream\" command");
		goto error;
	}

	/* Receive response. */
	ret = recv_reply(sock, &reply, sizeof(reply));
	if (ret < 0) {
		ERR("Failed to receive \"rotate streams\" command reply");
		goto error;
	}

	reply.ret_code = be32toh(reply.ret_code);
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd rotate streams replied error %d", reply.ret_code);
	} else {
		/* Success. */
		ret = 0;
		DBG("Relayd rotated streams successfully");
	}

error:
	lttng_dynamic_buffer_reset(&payload);
	return ret;
}

int relayd_create_trace_chunk(struct lttcomm_relayd_sock *sock,
		struct lttng_trace_chunk *chunk)
{
	int ret = 0;
	enum lttng_trace_chunk_status status;
	struct lttcomm_relayd_create_trace_chunk msg = {};
	struct lttcomm_relayd_generic_reply reply = {};
	struct lttng_dynamic_buffer payload;
	uint64_t chunk_id;
	time_t creation_timestamp;
	const char *chunk_name;
	size_t chunk_name_length;
	bool overridden_name;

	lttng_dynamic_buffer_init(&payload);

	if (!relayd_supports_chunks(sock)) {
		DBG("Refusing to create remote trace chunk: relayd does not support chunks");
		goto end;
	}

	status = lttng_trace_chunk_get_id(chunk, &chunk_id);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end;
	}

	status = lttng_trace_chunk_get_creation_timestamp(
			chunk, &creation_timestamp);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end;
	}

	status = lttng_trace_chunk_get_name(
			chunk, &chunk_name, &overridden_name);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK &&
			status != LTTNG_TRACE_CHUNK_STATUS_NONE) {
		ret = -1;
		goto end;
	}

	chunk_name_length = overridden_name ? (strlen(chunk_name) + 1) : 0;
	msg = (typeof(msg)){
		.chunk_id = htobe64(chunk_id),
		.creation_timestamp = htobe64((uint64_t) creation_timestamp),
		.override_name_length = htobe32((uint32_t) chunk_name_length),
	};

	ret = lttng_dynamic_buffer_append(&payload, &msg, sizeof(msg));
	if (ret) {
		goto end;
	}
	if (chunk_name_length) {
		ret = lttng_dynamic_buffer_append(
				&payload, chunk_name, chunk_name_length);
		if (ret) {
			goto end;
		}
	}

	ret = send_command(sock, RELAYD_CREATE_TRACE_CHUNK, payload.data,
			payload.size, 0);
	if (ret < 0) {
		ERR("Failed to send trace chunk creation command to relay daemon");
		goto end;
	}

	ret = recv_reply(sock, &reply, sizeof(reply));
	if (ret < 0) {
		ERR("Failed to receive relay daemon trace chunk creation command reply");
		goto end;
	}

	reply.ret_code = be32toh(reply.ret_code);
	if (reply.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd trace chunk create replied error %d",
				reply.ret_code);
	} else {
		ret = 0;
		DBG("Relayd successfully created trace chunk: chunk_id = %" PRIu64,
				chunk_id);
	}

end:
	lttng_dynamic_buffer_reset(&payload);
	return ret;
}

int relayd_close_trace_chunk(struct lttcomm_relayd_sock *sock,
		struct lttng_trace_chunk *chunk,
		char *path)
{
	int ret = 0;
	enum lttng_trace_chunk_status status;
	struct lttcomm_relayd_close_trace_chunk msg = {};
	struct lttcomm_relayd_close_trace_chunk_reply reply = {};
	uint64_t chunk_id;
	time_t close_timestamp;
	LTTNG_OPTIONAL(enum lttng_trace_chunk_command_type) close_command = {};

	if (!relayd_supports_chunks(sock)) {
		DBG("Refusing to close remote trace chunk: relayd does not support chunks");
		goto end;
	}

	status = lttng_trace_chunk_get_id(chunk, &chunk_id);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ERR("Failed to get trace chunk id");
		ret = -1;
		goto end;
	}

	status = lttng_trace_chunk_get_close_timestamp(chunk, &close_timestamp);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ERR("Failed to get trace chunk close timestamp");
		ret = -1;
		goto end;
	}

	status = lttng_trace_chunk_get_close_command(chunk,
			&close_command.value);
	switch (status) {
	case LTTNG_TRACE_CHUNK_STATUS_OK:
		close_command.is_set = 1;
		break;
	case LTTNG_TRACE_CHUNK_STATUS_NONE:
		break;
	default:
		ERR("Failed to get trace chunk close command");
		ret = -1;
		goto end;
	}

	msg = (typeof(msg)){
		.chunk_id = htobe64(chunk_id),
		.close_timestamp = htobe64((uint64_t) close_timestamp),
		.close_command = {
			.value = htobe32((uint32_t) close_command.value),
			.is_set = close_command.is_set,
		},
	};

	ret = send_command(sock, RELAYD_CLOSE_TRACE_CHUNK, &msg, sizeof(msg),
			0);
	if (ret < 0) {
		ERR("Failed to send trace chunk close command to relay daemon");
		goto end;
	}

	ret = recv_reply(sock, &reply, sizeof(reply));
	if (ret < 0) {
		ERR("Failed to receive relay daemon trace chunk close command reply");
		goto end;
	}

	reply.path_length = be32toh(reply.path_length);
	if (reply.path_length >= LTTNG_PATH_MAX) {
		ERR("Chunk path too long");
		ret = -1;
		goto end;
	}

	ret = recv_reply(sock, path, reply.path_length);
	if (ret < 0) {
		ERR("Failed to receive relay daemon trace chunk close command reply");
		goto end;
	}
	if (path[reply.path_length - 1] != '\0') {
		ERR("Invalid trace chunk path returned by relay daemon (not null-terminated)");
		ret = -1;
		goto end;
	}

	reply.generic.ret_code = be32toh(reply.generic.ret_code);
	if (reply.generic.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd trace chunk close replied error %d",
				reply.generic.ret_code);
	} else {
		ret = 0;
		DBG("Relayd successfully closed trace chunk: chunk_id = %" PRIu64,
				chunk_id);
	}
end:
	return ret;
}

int relayd_trace_chunk_exists(struct lttcomm_relayd_sock *sock,
		uint64_t chunk_id, bool *chunk_exists)
{
	int ret = 0;
	struct lttcomm_relayd_trace_chunk_exists msg = {};
	struct lttcomm_relayd_trace_chunk_exists_reply reply = {};

	if (!relayd_supports_chunks(sock)) {
		DBG("Refusing to check for trace chunk existence: relayd does not support chunks");
		/* The chunk will never exist */
		*chunk_exists = false;
		goto end;
	}

	msg = (typeof(msg)){
			.chunk_id = htobe64(chunk_id),
	};

	ret = send_command(sock, RELAYD_TRACE_CHUNK_EXISTS, &msg, sizeof(msg),
			0);
	if (ret < 0) {
		ERR("Failed to send trace chunk exists command to relay daemon");
		goto end;
	}

	ret = recv_reply(sock, &reply, sizeof(reply));
	if (ret < 0) {
		ERR("Failed to receive relay daemon trace chunk close command reply");
		goto end;
	}

	reply.generic.ret_code = be32toh(reply.generic.ret_code);
	if (reply.generic.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd trace chunk close replied error %d",
				reply.generic.ret_code);
	} else {
		ret = 0;
		DBG("Relayd successfully checked trace chunk existence: chunk_id = %" PRIu64
				", exists = %s", chunk_id,
				reply.trace_chunk_exists ? "true" : "false");
		*chunk_exists = !!reply.trace_chunk_exists;
	}
end:
	return ret;
}

int relayd_get_configuration(struct lttcomm_relayd_sock *sock,
		uint64_t query_flags,
		uint64_t *result_flags)
{
	int ret = 0;
	struct lttcomm_relayd_get_configuration msg = (typeof(msg)) {
		.query_flags = htobe64(query_flags),
	};
	struct lttcomm_relayd_get_configuration_reply reply = {};

	if (!relayd_supports_get_configuration(sock)) {
		DBG("Refusing to get relayd configuration (unsupported by relayd)");
		if (query_flags) {
			ret = -1;
			goto end;
		}
		*result_flags = 0;
		goto end;
	}

	ret = send_command(sock, RELAYD_GET_CONFIGURATION, &msg, sizeof(msg),
			0);
	if (ret < 0) {
		ERR("Failed to send get configuration command to relay daemon");
		goto end;
	}

	ret = recv_reply(sock, &reply, sizeof(reply));
	if (ret < 0) {
		ERR("Failed to receive relay daemon get configuration command reply");
		goto end;
	}

	reply.generic.ret_code = be32toh(reply.generic.ret_code);
	if (reply.generic.ret_code != LTTNG_OK) {
		ret = -1;
		ERR("Relayd get configuration replied error %d",
				reply.generic.ret_code);
	} else {
		reply.relayd_configuration_flags =
			be64toh(reply.relayd_configuration_flags);
		ret = 0;
		DBG("Relayd successfully got configuration: query_flags = %" PRIu64
				", results_flags = %" PRIu64, query_flags,
				reply.relayd_configuration_flags);
		*result_flags = reply.relayd_configuration_flags;
	}
end:
	return ret;
}
