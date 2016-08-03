/*
 * Copyright (c) - 2013 Julien Desfossez <jdesfossez@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by as
 * published by the Free Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <common/compat/time.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <tap/tap.h>
#include <lttng/lttng.h>

#include <urcu/list.h>
#include <bin/lttng-sessiond/session.h>
#include <common/common.h>

#include <bin/lttng-relayd/lttng-viewer-abi.h>
#include <common/index/ctf-index.h>

#include <common/compat/endian.h>

#define SESSION1 "test1"
#define RELAYD_URL "net://localhost"
#define LIVE_TIMER 2000000

/* Number of TAP tests in this file */
#define NUM_TESTS 11
#define mmap_size 524288

int ust_consumerd32_fd;
int ust_consumerd64_fd;

static int control_sock;
struct live_session *session;

static int first_packet_offset;
static int first_packet_len;
static int first_packet_stream_id = -1;

struct viewer_stream {
	uint64_t id;
	uint64_t ctf_trace_id;
	void *mmap_base;
	int fd;
	int metadata_flag;
	int first_read;
	char path[PATH_MAX];
};

struct live_session {
	struct viewer_stream *streams;
	uint64_t live_timer_interval;
	uint64_t stream_count;
};

static
ssize_t lttng_live_recv(int fd, void *buf, size_t len)
{
	ssize_t ret;
	size_t copied = 0, to_copy = len;

	do {
		ret = recv(fd, buf + copied, to_copy, 0);
		if (ret > 0) {
			assert(ret <= to_copy);
			copied += ret;
			to_copy -= ret;
		}
	} while ((ret > 0 && to_copy > 0)
		|| (ret < 0 && errno == EINTR));
	if (ret > 0)
		ret = copied;
	/* ret = 0 means orderly shutdown, ret < 0 is error. */
	return ret;
}

static
ssize_t lttng_live_send(int fd, const void *buf, size_t len)
{
	ssize_t ret;

	do {
		ret = send(fd, buf, len, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);
	return ret;
}

static
int connect_viewer(char *hostname)
{
	struct hostent *host;
	struct sockaddr_in server_addr;
	int ret;

	host = gethostbyname(hostname);
	if (!host) {
		ret = -1;
		goto end;
	}

	if ((control_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		PERROR("Socket");
		ret = -1;
		goto end;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(5344);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	bzero(&(server_addr.sin_zero), 8);

	if (connect(control_sock, (struct sockaddr *) &server_addr,
				sizeof(struct sockaddr)) == -1) {
		PERROR("Connect");
		ret = -1;
		goto end;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(5345);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	bzero(&(server_addr.sin_zero), 8);

	ret = 0;

end:
	return ret;
}

int establish_connection(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_connect connect;
	ssize_t ret_len;

	cmd.cmd = htobe32(LTTNG_VIEWER_CONNECT);
	cmd.data_size = htobe64(sizeof(connect));
	cmd.cmd_version = htobe32(0);

	memset(&connect, 0, sizeof(connect));
	connect.major = htobe32(VERSION_MAJOR);
	connect.minor = htobe32(VERSION_MINOR);
	connect.type = htobe32(LTTNG_VIEWER_CLIENT_COMMAND);

	ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
	if (ret_len < 0) {
		diag("Error sending cmd");
		goto error;
	}
	ret_len = lttng_live_send(control_sock, &connect, sizeof(connect));
	if (ret_len < 0) {
		diag("Error sending version");
		goto error;
	}

	ret_len = lttng_live_recv(control_sock, &connect, sizeof(connect));
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error;
	}
	if (ret_len < 0) {
		diag("Error receiving version");
		goto error;
	}
	return 0;

error:
	return -1;
}

/*
 * Returns the number of sessions, should be 1 during the unit test.
 */
int list_sessions(uint64_t *session_id)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_list_sessions list;
	struct lttng_viewer_session lsession;
	int i;
	ssize_t ret_len;
	int first_session = 0;

	cmd.cmd = htobe32(LTTNG_VIEWER_LIST_SESSIONS);
	cmd.data_size = htobe64(0);
	cmd.cmd_version = htobe32(0);

	ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
	if (ret_len < 0) {
		diag("Error sending cmd");
		goto error;
	}

	ret_len = lttng_live_recv(control_sock, &list, sizeof(list));
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error;
	}
	if (ret_len < 0) {
		diag("Error receiving session list");
		goto error;
	}

	for (i = 0; i < be32toh(list.sessions_count); i++) {
		ret_len = lttng_live_recv(control_sock, &lsession, sizeof(lsession));
		if (ret_len < 0) {
			diag("Error receiving session");
			goto error;
		}
		if (lsession.streams > 0 && first_session <= 0) {
			first_session = be64toh(lsession.id);
			*session_id = first_session;
		}
	}

	return be32toh(list.sessions_count);

error:
	return -1;
}

int create_viewer_session(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_create_session_response resp;
	ssize_t ret_len;

	cmd.cmd = htobe32(LTTNG_VIEWER_CREATE_SESSION);
	cmd.data_size = htobe64(0);
	cmd.cmd_version = htobe32(0);

	ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
	if (ret_len < 0) {
		diag("[error] Error sending cmd");
		goto error;
	}
	assert(ret_len == sizeof(cmd));

	ret_len = lttng_live_recv(control_sock, &resp, sizeof(resp));
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error;
	}
	if (ret_len < 0) {
		diag("[error] Error receiving create session reply");
		goto error;
	}
	assert(ret_len == sizeof(resp));

	if (be32toh(resp.status) != LTTNG_VIEWER_CREATE_SESSION_OK) {
		diag("[error] Error creating viewer session");
		goto error;
	}
	return 0;

error:
	return -1;
}

int attach_session(uint64_t id)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_attach_session_request rq;
	struct lttng_viewer_attach_session_response rp;
	struct lttng_viewer_stream stream;
	int i;
	ssize_t ret_len;

	session = zmalloc(sizeof(struct live_session));
	if (!session) {
		goto error;
	}

	cmd.cmd = htobe32(LTTNG_VIEWER_ATTACH_SESSION);
	cmd.data_size = htobe64(sizeof(rq));
	cmd.cmd_version = htobe32(0);

	memset(&rq, 0, sizeof(rq));
	rq.session_id = htobe64(id);
	rq.seek = htobe32(LTTNG_VIEWER_SEEK_BEGINNING);

	ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
	if (ret_len < 0) {
		diag("Error sending cmd LTTNG_VIEWER_ATTACH_SESSION");
		goto error;
	}
	ret_len = lttng_live_send(control_sock, &rq, sizeof(rq));
	if (ret_len < 0) {
		diag("Error sending attach request");
		goto error;
	}

	ret_len = lttng_live_recv(control_sock, &rp, sizeof(rp));
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error;
	}
	if (ret_len < 0) {
		diag("Error receiving attach response");
		goto error;
	}
	if (be32toh(rp.status) != LTTNG_VIEWER_ATTACH_OK) {
		goto error;
	}

	session->stream_count = be32toh(rp.streams_count);
	if (session->stream_count == 0) {
		diag("Got session stream count == 0");
		goto error;
	}
	session->streams = zmalloc(session->stream_count *
			sizeof(struct viewer_stream));
	if (!session->streams) {
		goto error;
	}

	for (i = 0; i < be32toh(rp.streams_count); i++) {
		ret_len = lttng_live_recv(control_sock, &stream, sizeof(stream));
		if (ret_len == 0) {
			diag("[error] Remote side has closed connection");
			goto error;
		}
		if (ret_len < 0) {
			diag("Error receiving stream");
			goto error;
		}
		session->streams[i].id = be64toh(stream.id);

		session->streams[i].ctf_trace_id = be64toh(stream.ctf_trace_id);
		session->streams[i].first_read = 1;
		session->streams[i].mmap_base = mmap(NULL, mmap_size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (session->streams[i].mmap_base == MAP_FAILED) {
			diag("mmap error");
			goto error;
		}

		if (be32toh(stream.metadata_flag)) {
			session->streams[i].metadata_flag = 1;
		}
	}
	return session->stream_count;

error:
	return -1;
}

int get_metadata(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_metadata rq;
	struct lttng_viewer_metadata_packet rp;
	ssize_t ret_len;
	int ret;
	uint64_t i;
	char *data = NULL;
	uint64_t len = 0;
	int metadata_stream_id = -1;

	cmd.cmd = htobe32(LTTNG_VIEWER_GET_METADATA);
	cmd.data_size = htobe64(sizeof(rq));
	cmd.cmd_version = htobe32(0);

	for (i = 0; i < session->stream_count; i++) {
		if (session->streams[i].metadata_flag) {
			metadata_stream_id = i;
			break;
		}
	}

	if (metadata_stream_id < 0) {
		diag("No metadata stream found");
		goto error;
	}

	rq.stream_id = htobe64(session->streams[metadata_stream_id].id);

	ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
	if (ret_len < 0) {
		diag("Error sending cmd");
		goto error;
	}
	ret_len = lttng_live_send(control_sock, &rq, sizeof(rq));
	if (ret_len < 0) {
		diag("Error sending get_metadata request");
		goto error;
	}
	ret_len = lttng_live_recv(control_sock, &rp, sizeof(rp));
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error;
	}
	if (ret_len < 0) {
		diag("Error receiving metadata response");
		goto error;
	}
	switch (be32toh(rp.status)) {
	case LTTNG_VIEWER_METADATA_OK:
		break;
	case LTTNG_VIEWER_NO_NEW_METADATA:
		diag("Got LTTNG_VIEWER_NO_NEW_METADATA:");
		ret = 0;
		goto end;
	case LTTNG_VIEWER_METADATA_ERR:
		diag("Got LTTNG_VIEWER_METADATA_ERR:");
		goto error;
	default:
		diag("Got unknown status during LTTNG_VIEWER_GET_METADATA");
		goto error;
	}

	len = be64toh(rp.len);
	if (len <= 0) {
		goto error;
	}

	data = zmalloc(len);
	if (!data) {
		PERROR("relay data zmalloc");
		goto error;
	}
	ret_len = lttng_live_recv(control_sock, data, len);
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error_free_data;
	}
	if (ret_len < 0) {
		diag("Error receiving trace packet");
		goto error_free_data;
	}
	free(data);
	ret = len;
end:
	return ret;

error_free_data:
	free(data);
error:
	return -1;
}

int get_next_index(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_next_index rq;
	struct lttng_viewer_index rp;
	ssize_t ret_len;
	int id;

	cmd.cmd = htobe32(LTTNG_VIEWER_GET_NEXT_INDEX);
	cmd.data_size = htobe64(sizeof(rq));
	cmd.cmd_version = htobe32(0);

	for (id = 0; id < session->stream_count; id++) {
		if (session->streams[id].metadata_flag) {
			continue;
		}
		memset(&rq, 0, sizeof(rq));
		rq.stream_id = htobe64(session->streams[id].id);

retry:
		ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
		if (ret_len < 0) {
			diag("Error sending cmd");
			goto error;
		}
		ret_len = lttng_live_send(control_sock, &rq, sizeof(rq));
		if (ret_len < 0) {
			diag("Error sending get_next_index request");
			goto error;
		}
		ret_len = lttng_live_recv(control_sock, &rp, sizeof(rp));
		if (ret_len == 0) {
			diag("[error] Remote side has closed connection");
			goto error;
		}
		if (ret_len < 0) {
			diag("Error receiving index response");
			goto error;
		}

		rp.flags = be32toh(rp.flags);

		switch (be32toh(rp.status)) {
		case LTTNG_VIEWER_INDEX_INACTIVE:
			/* Skip this stream. */
			diag("Got LTTNG_VIEWER_INDEX_INACTIVE");
			continue;
		case LTTNG_VIEWER_INDEX_OK:
			break;
		case LTTNG_VIEWER_INDEX_RETRY:
			sleep(1);
			goto retry;
		case LTTNG_VIEWER_INDEX_HUP:
			diag("Got LTTNG_VIEWER_INDEX_HUP");
			session->streams[id].id = -1ULL;
			session->streams[id].fd = -1;
			goto error;
		case LTTNG_VIEWER_INDEX_ERR:
			diag("Got LTTNG_VIEWER_INDEX_ERR");
			goto error;
		default:
			diag("Unknown reply status during LTTNG_VIEWER_GET_NEXT_INDEX (%d)", be32toh(rp.status));
			goto error;
		}
		if (first_packet_stream_id < 0) {
			/*
			 * Initialize the first packet stream id. That is,
			 * the first active stream encoutered.
			 */
			first_packet_offset = be64toh(rp.offset);
			first_packet_len = be64toh(rp.packet_size) / CHAR_BIT;
			first_packet_stream_id = id;
			diag("Got first packet index with offset %d and len %d",
					first_packet_offset, first_packet_len);
		}
	}
	return 0;

error:
	return -1;
}

static
int get_data_packet(int id, uint64_t offset,
		uint64_t len)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_packet rq;
	struct lttng_viewer_trace_packet rp;
	ssize_t ret_len;

	cmd.cmd = htobe32(LTTNG_VIEWER_GET_PACKET);
	cmd.data_size = htobe64(sizeof(rq));
	cmd.cmd_version = htobe32(0);

	memset(&rq, 0, sizeof(rq));
	rq.stream_id = htobe64(session->streams[id].id);
	/* Already in big endian. */
	rq.offset = offset;
	rq.len = htobe32(len);

	ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
	if (ret_len < 0) {
		diag("Error sending cmd");
		goto error;
	}
	ret_len = lttng_live_send(control_sock, &rq, sizeof(rq));
	if (ret_len < 0) {
		diag("Error sending get_data_packet request");
		goto error;
	}
	ret_len = lttng_live_recv(control_sock, &rp, sizeof(rp));
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error;
	}
	if (ret_len < 0) {
		diag("Error receiving data response");
		goto error;
	}
	rp.flags = be32toh(rp.flags);

	switch (be32toh(rp.status)) {
	case LTTNG_VIEWER_GET_PACKET_OK:
		len = be32toh(rp.len);
		if (len == 0) {
			diag("Got LTTNG_VIEWER_GET_PACKET_OK, but len == 0");
			goto error;
		}
		break;
	case LTTNG_VIEWER_GET_PACKET_RETRY:
		diag("Got LTTNG_VIEWER_GET_PACKET_RETRY:");
		goto error;
	case LTTNG_VIEWER_GET_PACKET_ERR:
		if (rp.flags & LTTNG_VIEWER_FLAG_NEW_METADATA) {
			diag("Got LTTNG_VIEWER_GET_PACKET_ERR with NEW_METADATA flag");
			goto end;
		}
		diag("Got LTTNG_VIEWER_GET_PACKET_ERR:");
		goto error;
	default:
		diag("Got unknown status code during LTTNG_VIEWER_GET_PACKET");
		goto error;
	}

	if (len > mmap_size) {
		diag("mmap_size not big enough");
		goto error;
	}

	ret_len = lttng_live_recv(control_sock, session->streams[id].mmap_base, len);
	if (ret_len == 0) {
		diag("[error] Remote side has closed connection");
		goto error;
	}
	if (ret_len < 0) {
		diag("Error receiving trace packet");
		goto error;
	}
end:
	return 0;
error:
	return -1;
}

int detach_viewer_session(uint64_t id)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_detach_session_response resp;
	struct lttng_viewer_detach_session_request rq;
	int ret;
	ssize_t ret_len;

	cmd.cmd = htobe32(LTTNG_VIEWER_DETACH_SESSION);
	cmd.data_size = htobe64(sizeof(rq));
	cmd.cmd_version = htobe32(0);

	memset(&rq, 0, sizeof(rq));
	rq.session_id = htobe64(id);

	ret_len = lttng_live_send(control_sock, &cmd, sizeof(cmd));
	if (ret_len < 0) {
		fprintf(stderr, "[error] Error sending cmd\n");
		ret = ret_len;
		goto error;
	}

	ret_len = lttng_live_send(control_sock, &rq, sizeof(rq));
	if (ret_len < 0) {
		fprintf(stderr, "Error sending attach request\n");
		ret = ret_len;
		goto error;
	}

	ret_len = lttng_live_recv(control_sock, &resp, sizeof(resp));
	if (ret_len < 0) {
		fprintf(stderr, "[error] Error receiving detach session reply\n");
		ret = ret_len;
		goto error;
	}

	if (be32toh(resp.status) != LTTNG_VIEWER_DETACH_SESSION_OK) {
		fprintf(stderr, "[error] Error detaching viewer session\n");
		ret = -1;
		goto error;
	}
	ret = 0;

error:
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	uint64_t session_id;

	plan_tests(NUM_TESTS);

	diag("Live unit tests");

	ret = connect_viewer("localhost");
	ok(ret == 0, "Connect viewer to relayd");

	ret = establish_connection();
	ok(ret == 0, "Established connection and version check with %d.%d",
			VERSION_MAJOR, VERSION_MINOR);

	ret = list_sessions(&session_id);
	ok(ret > 0, "List sessions : %d session(s)", ret);

	ret = create_viewer_session();
	ok(ret == 0, "Create viewer session");

	ret = attach_session(session_id);
	ok(ret > 0, "Attach to session, %d stream(s) received", ret);

	ret = get_metadata();
	ok(ret > 0, "Get metadata, received %d bytes", ret);

	ret = get_next_index();
	ok(ret == 0, "Get one index per stream");

	ret = get_data_packet(first_packet_stream_id, first_packet_offset,
			first_packet_len);
	ok(ret == 0,
			"Get one data packet for stream %d, offset %d, len %d",
			first_packet_stream_id, first_packet_offset,
			first_packet_len);

	ret = detach_viewer_session(session_id);
	ok(ret == 0, "Detach viewer session");

	ret = list_sessions(&session_id);
	ok(ret > 0, "List sessions : %d session(s)", ret);

	ret = attach_session(session_id);
	ok(ret > 0, "Attach to session, %d streams received", ret);

	return exit_status();
}
