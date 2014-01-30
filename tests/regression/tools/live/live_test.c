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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
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

#define SESSION1 "test1"
#define RELAYD_URL "net://localhost"
#define LIVE_TIMER 2000000

/* Number of TAP tests in this file */
#define NUM_TESTS 7
#define mmap_size 524288

int ust_consumerd32_fd;
int ust_consumerd64_fd;

static int control_sock;
struct live_session *session;

static int first_packet_offset;
static int first_packet_len;
static int first_packet_stream_id;

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
		perror("Socket");
		ret = -1;
		goto end;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(5344);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	bzero(&(server_addr.sin_zero), 8);

	if (connect(control_sock, (struct sockaddr *) &server_addr,
				sizeof(struct sockaddr)) == -1) {
		perror("Connect");
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
	int ret;

	cmd.cmd = htobe32(LTTNG_VIEWER_CONNECT);
	cmd.data_size = sizeof(connect);
	cmd.cmd_version = 0;

	memset(&connect, 0, sizeof(connect));
	connect.major = htobe32(VERSION_MAJOR);
	connect.minor = htobe32(VERSION_MINOR);
	connect.type = htobe32(LTTNG_VIEWER_CLIENT_COMMAND);

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &connect, sizeof(connect), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending version\n");
		goto error;
	}

	do {
		ret = recv(control_sock, &connect, sizeof(connect), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving version\n");
		goto error;
	}
	ret = 0;

error:
	return ret;
}

/*
 * Returns the number of sessions, should be 1 during the unit test.
 */
int list_sessions(int *session_id)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_list_sessions list;
	struct lttng_viewer_session lsession;
	int i, ret;
	int first_session = 0;

	cmd.cmd = htobe32(LTTNG_VIEWER_LIST_SESSIONS);
	cmd.data_size = 0;
	cmd.cmd_version = 0;

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}

	do {
		ret = recv(control_sock, &list, sizeof(list), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving session list\n");
		goto error;
	}

	for (i = 0; i < be32toh(list.sessions_count); i++) {
		do {
			ret = recv(control_sock, &lsession, sizeof(lsession), 0);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			fprintf(stderr, "Error receiving session\n");
			goto error;
		}
		if (lsession.streams > 0 && first_session <= 0) {
			first_session = be64toh(lsession.id);
			*session_id = first_session;
		}
	}

	ret = be32toh(list.sessions_count);

error:
	return ret;
}

int attach_session(int id)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_attach_session_request rq;
	struct lttng_viewer_attach_session_response rp;
	struct lttng_viewer_stream stream;
	int ret, i;

	session = zmalloc(sizeof(struct live_session));
	if (!session) {
		ret = -1;
		goto error;
	}

	cmd.cmd = htobe32(LTTNG_VIEWER_ATTACH_SESSION);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	memset(&rq, 0, sizeof(rq));
	rq.session_id = htobe64(id);
	rq.seek = htobe32(LTTNG_VIEWER_SEEK_BEGINNING);

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &rq, sizeof(rq), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending attach request\n");
		goto error;
	}

	do {
		ret = recv(control_sock, &rp, sizeof(rp), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving attach response\n");
		goto error;
	}
	if (be32toh(rp.status) != LTTNG_VIEWER_ATTACH_OK) {
		ret = -1;
		goto end;
	}

	session->stream_count = be32toh(rp.streams_count);
	session->streams = zmalloc(session->stream_count *
			sizeof(struct viewer_stream));
	if (!session->streams) {
		ret = -1;
		goto error;
	}

	for (i = 0; i < be32toh(rp.streams_count); i++) {
		do {
			ret = recv(control_sock, &stream, sizeof(stream), 0);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			fprintf(stderr, "Error receiving stream\n");
			goto error;
		}
		session->streams[i].id = be64toh(stream.id);

		session->streams[i].ctf_trace_id = be64toh(stream.ctf_trace_id);
		session->streams[i].first_read = 1;
		session->streams[i].mmap_base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (session->streams[i].mmap_base == MAP_FAILED) {
			fprintf(stderr, "mmap error\n");
			ret = -1;
			goto error;
		}

		if (be32toh(stream.metadata_flag)) {
			session->streams[i].metadata_flag = 1;
		}
	}
	ret = session->stream_count;

end:
error:
	return ret;
}

int get_metadata(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_metadata rq;
	struct lttng_viewer_metadata_packet rp;
	int ret;
	uint64_t i;
	char *data = NULL;
	uint64_t len = 0;
	int metadata_stream_id = -1;

	cmd.cmd = htobe32(LTTNG_VIEWER_GET_METADATA);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	for (i = 0; i < session->stream_count; i++) {
		if (session->streams[i].metadata_flag) {
			metadata_stream_id = i;
			break;
		}
	}

	if (metadata_stream_id < 0) {
		fprintf(stderr, "No metadata stream found\n");
		ret = -1;
		goto error;
	}

	rq.stream_id = htobe64(session->streams[metadata_stream_id].id);

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &rq, sizeof(rq), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending get_metadata request\n");
		goto error;
	}
	do {
		ret = recv(control_sock, &rp, sizeof(rp), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving metadata response\n");
		goto error;
	}
	switch (be32toh(rp.status)) {
		case LTTNG_VIEWER_METADATA_OK:
			break;
		case LTTNG_VIEWER_NO_NEW_METADATA:
			fprintf(stderr, "NO NEW\n");
			ret = -1;
			goto end;
		case LTTNG_VIEWER_METADATA_ERR:
			fprintf(stderr, "ERR\n");
			ret = -1;
			goto end;
		default:
			fprintf(stderr, "UNKNOWN\n");
			ret = -1;
			goto end;
	}

	len = be64toh(rp.len);
	if (len <= 0) {
		goto end;
	}

	data = zmalloc(len);
	if (!data) {
		perror("relay data zmalloc");
		goto error;
	}
	do {
		ret = recv(control_sock, data, len, MSG_WAITALL);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving trace packet\n");
		free(data);
		goto error;
	}
	free(data);

	ret = (int) len;
end:
error:
	return ret;
}

int get_next_index(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_next_index rq;
	struct lttng_viewer_index rp;
	int ret;
	int id;

	cmd.cmd = htobe32(LTTNG_VIEWER_GET_NEXT_INDEX);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	for (id = 0; id < session->stream_count; id++) {
		if (session->streams[id].metadata_flag) {
			continue;
		}
		rq.stream_id = htobe64(session->streams[id].id);

retry:
		do {
			ret = send(control_sock, &cmd, sizeof(cmd), 0);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			fprintf(stderr, "Error sending cmd\n");
			goto error;
		}
		do {
			ret = send(control_sock, &rq, sizeof(rq), 0);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			fprintf(stderr, "Error sending get_next_index request\n");
			goto error;
		}
		do {
			ret = recv(control_sock, &rp, sizeof(rp), 0);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			fprintf(stderr, "Error receiving index response\n");
			goto error;
		}

		rp.flags = be32toh(rp.flags);

		switch (be32toh(rp.status)) {
			case LTTNG_VIEWER_INDEX_INACTIVE:
				fprintf(stderr, "(INACTIVE)\n");
				break;
			case LTTNG_VIEWER_INDEX_OK:
				break;
			case LTTNG_VIEWER_INDEX_RETRY:
				sleep(1);
				goto retry;
			case LTTNG_VIEWER_INDEX_HUP:
				fprintf(stderr, "(HUP)\n");
				session->streams[id].id = -1ULL;
				session->streams[id].fd = -1;
				break;
			case LTTNG_VIEWER_INDEX_ERR:
				fprintf(stderr, "(ERR)\n");
				ret = -1;
				goto error;
			default:
				fprintf(stderr, "SHOULD NOT HAPPEN\n");
				ret = -1;
				goto error;
		}
		if (!first_packet_stream_id) {
			first_packet_offset = be64toh(rp.offset);
			first_packet_len = be64toh(rp.packet_size) / CHAR_BIT;
			first_packet_stream_id = id;
		}
	}
	ret = 0;

error:
	return ret;
}

static
int get_data_packet(int id, uint64_t offset,
		uint64_t len)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_packet rq;
	struct lttng_viewer_trace_packet rp;
	int ret;

	cmd.cmd = htobe32(LTTNG_VIEWER_GET_PACKET);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	rq.stream_id = htobe64(session->streams[id].id);
	/* Already in big endian. */
	rq.offset = offset;
	rq.len = htobe32(len);

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &rq, sizeof(rq), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending get_data_packet request\n");
		goto error;
	}
	do {
		ret = recv(control_sock, &rp, sizeof(rp), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving data response\n");
		goto error;
	}
	rp.flags = be32toh(rp.flags);

	switch (be32toh(rp.status)) {
	case LTTNG_VIEWER_GET_PACKET_OK:
		break;
	case LTTNG_VIEWER_GET_PACKET_RETRY:
		fprintf(stderr, "RETRY\n");
		ret = -1;
		goto end;
	case LTTNG_VIEWER_GET_PACKET_ERR:
		if (rp.flags & LTTNG_VIEWER_FLAG_NEW_METADATA) {
			fprintf(stderr, "NEW_METADATA\n");
			ret = 0;
			goto end;
		}
		fprintf(stderr, "ERR\n");
		ret = -1;
		goto end;
	default:
		fprintf(stderr, "UNKNOWN\n");
		ret = -1;
		goto end;
	}

	len = be32toh(rp.len);
	if (len <= 0) {
		goto end;
	}

	if (len > mmap_size) {
		fprintf(stderr, "mmap_size not big enough\n");
		ret = -1;
		goto error;
	}

	do {
		ret = recv(control_sock, session->streams[id].mmap_base, len, MSG_WAITALL);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving trace packet\n");
		goto error;
	}
	ret = len;

end:
error:
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	int session_id;

	plan_tests(NUM_TESTS);

	diag("Live unit tests");

	ret = connect_viewer("localhost");
	ok(ret == 0, "Connect viewer to relayd");

	ret = establish_connection();
	ok(ret == 0, "Established connection and version check with %d.%d",
			VERSION_MAJOR, VERSION_MINOR);

	ret = list_sessions(&session_id);
	ok(ret > 0, "List sessions : %d session(s)", ret);

	ret = attach_session(session_id);
	ok(ret > 0, "Attach to session, %d streams received", ret);

	ret = get_metadata();
	ok(ret > 0, "Get metadata, received %d bytes", ret);

	ret = get_next_index();
	ok(ret == 0, "Get one index per stream");

	ret = get_data_packet(first_packet_stream_id, first_packet_offset,
			first_packet_len);
	ok(ret == first_packet_len,
			"Get one data packet for stream %d, offset %d, len %d",
			first_packet_stream_id, first_packet_offset,
			first_packet_len);

	return exit_status();
}
