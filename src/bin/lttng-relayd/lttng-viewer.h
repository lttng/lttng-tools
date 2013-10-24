/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef LTTNG_VIEWER_H
#define LTTNG_VIEWER_H

#include <limits.h>

#define LTTNG_VIEWER_PATH_MAX		4096
#define LTTNG_VIEWER_NAME_MAX		255
#define LTTNG_VIEWER_HOST_NAME_MAX	64

/* Flags in reply to get_next_index and get_packet. */
/* New metadata is required to read this packet. */
#define LTTNG_VIEWER_FLAG_NEW_METADATA	(1 << 0)
/* New stream got added to the trace */
#define LTTNG_VIEWER_FLAG_NEW_STREAM	(1 << 1)

enum lttng_viewer_command {
	VIEWER_CONNECT		= 1,
	VIEWER_LIST_SESSIONS	= 2,
	VIEWER_ATTACH_SESSION	= 3,
	VIEWER_GET_NEXT_INDEX	= 4,
	VIEWER_GET_PACKET	= 5,
	VIEWER_GET_METADATA	= 6,
};

enum lttng_viewer_attach_return_code {
	VIEWER_ATTACH_OK	= 1, /* If the attach command succeeded. */
	VIEWER_ATTACH_ALREADY	= 2, /* If a viewer is already attached. */
	VIEWER_ATTACH_UNK	= 3, /* If the session ID is unknown. */
	VIEWER_ATTACH_NOT_LIVE	= 4, /* If the session is not live. */
	VIEWER_ATTACH_SEEK_ERR	= 5, /* Seek error. */
};

enum lttng_viewer_next_index_return_code {
	VIEWER_INDEX_OK		= 1, /* Index is available. */
	VIEWER_INDEX_RETRY	= 2, /* Index not yet available. */
	VIEWER_INDEX_HUP	= 3, /* Index closed (trace destroyed). */
	VIEWER_INDEX_ERR	= 4, /* Unknow error. */
	VIEWER_INDEX_INACTIVE	= 5, /* Inactive stream beacon. */
};

enum lttng_viewer_get_packet_return_code {
	VIEWER_GET_PACKET_OK		= 1,
	VIEWER_GET_PACKET_RETRY		= 2,
	VIEWER_GET_PACKET_ERR		= 3,
};

enum lttng_viewer_get_metadata_return_code {
	VIEWER_METADATA_OK	= 1,
	VIEWER_NO_NEW_METADATA	= 2,
	VIEWER_METADATA_ERR	= 3,
};

enum lttng_viewer_connection_type {
	VIEWER_CLIENT_COMMAND		= 1,
	VIEWER_CLIENT_NOTIFICATION	= 2,
};

enum lttng_viewer_seek {
	VIEWER_SEEK_BEGINNING	= 1,	/* Receive the trace packets from the beginning. */
	VIEWER_SEEK_LAST	= 2,	/* Receive the trace packets from now. */
};

struct lttng_viewer_session {
	uint64_t id;
	char hostname[LTTNG_VIEWER_HOST_NAME_MAX];
	char session_name[LTTNG_VIEWER_NAME_MAX];
	uint32_t live_timer;
	uint32_t clients;
} __attribute__((__packed__));

struct lttng_viewer_stream {
	uint64_t id;
	uint64_t ctf_trace_id;
	char path_name[LTTNG_VIEWER_PATH_MAX];
	char channel_name[LTTNG_VIEWER_NAME_MAX];
	int metadata_flag;
} __attribute__((__packed__));

struct lttng_viewer_cmd {
	uint64_t data_size;	/* data size following this header */
	uint32_t cmd;		/* enum lttcomm_relayd_command */
	uint32_t cmd_version;	/* command version */
} __attribute__((__packed__));

/*
 * CONNECT payload.
 */
struct lttng_viewer_connect {
	uint32_t major;
	uint32_t minor;
	uint32_t type; /* enum lttng_viewer_connection_type */
	uint64_t viewer_session_id; /* session ID assigned by the relay for command connections */
} __attribute__((__packed__));

/*
 * VIEWER_LIST_SESSIONS payload.
 */
struct lttng_viewer_list_sessions {
	uint32_t sessions_count;
	char session_list[];		/* struct lttng_viewer_session */
} __attribute__((__packed__));

/*
 * VIEWER_ATTACH_SESSION payload.
 */
struct lttng_viewer_attach_session_request {
	uint64_t session_id;
	uint32_t seek;		/* enum lttng_viewer_seek */
	uint64_t offset;	/* unused for now */
} __attribute__((__packed__));

struct lttng_viewer_attach_session_response {
	uint32_t status;		/* enum lttng_viewer_attach_return_code */
	uint32_t streams_count;
	char stream_list[];		/* struct lttng_viewer_stream */
} __attribute__((__packed__));

/*
 * VIEWER_GET_NEXT_INDEX payload.
 */
struct lttng_viewer_get_next_index {
	uint64_t stream_id;
} __attribute__ ((__packed__));

struct lttng_viewer_index {
	uint32_t status;	/* enum lttng_viewer_next_index_return_code */
	uint64_t offset;
	uint64_t packet_size;
	uint64_t content_size;
	uint64_t timestamp_begin;
	uint64_t timestamp_end;
	uint64_t events_discarded;
	uint64_t stream_id;
	uint32_t flags;	/* LTTNG_VIEWER_FLAG_* */
} __attribute__ ((__packed__));

/*
 * VIEWER_GET_PACKET payload.
 */
struct lttng_viewer_get_packet {
	uint64_t stream_id;
	uint64_t offset;
	uint32_t len;
} __attribute__((__packed__));

struct lttng_viewer_trace_packet {
	uint32_t status;		/* enum lttng_viewer_get_packet_return_code */
	uint32_t len;
	uint32_t flags;	/* LTTNG_VIEWER_FLAG_* */
	char data[];
} __attribute__((__packed__));

/*
 * VIEWER_GET_METADATA payload.
 */
struct lttng_viewer_get_metadata {
	uint64_t stream_id;
} __attribute__((__packed__));

struct lttng_viewer_metadata_packet {
	uint32_t status;		/* enum lttng_viewer_get_metadata_return_code */
	uint64_t len;
	char data[];
} __attribute__((__packed__));

#endif /* LTTNG_VIEWER_H */
