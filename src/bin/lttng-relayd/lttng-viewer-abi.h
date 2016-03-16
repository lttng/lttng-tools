#ifndef LTTNG_VIEWER_ABI_H
#define LTTNG_VIEWER_ABI_H

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

#include <limits.h>
#include <common/macros.h>

#define LTTNG_VIEWER_PATH_MAX		4096
#define LTTNG_VIEWER_NAME_MAX		255
#define LTTNG_VIEWER_HOST_NAME_MAX	64

/* Flags in reply to get_next_index and get_packet. */
enum {
	/* New metadata is required to read this packet. */
	LTTNG_VIEWER_FLAG_NEW_METADATA	= (1 << 0),
	/* New stream got added to the trace. */
	LTTNG_VIEWER_FLAG_NEW_STREAM	= (1 << 1),
};

enum lttng_viewer_command {
	LTTNG_VIEWER_CONNECT		= 1,
	LTTNG_VIEWER_LIST_SESSIONS	= 2,
	LTTNG_VIEWER_ATTACH_SESSION	= 3,
	LTTNG_VIEWER_GET_NEXT_INDEX	= 4,
	LTTNG_VIEWER_GET_PACKET		= 5,
	LTTNG_VIEWER_GET_METADATA	= 6,
	LTTNG_VIEWER_GET_NEW_STREAMS	= 7,
	LTTNG_VIEWER_CREATE_SESSION	= 8,
	LTTNG_VIEWER_DETACH_SESSION	= 9,
};

enum lttng_viewer_attach_return_code {
	LTTNG_VIEWER_ATTACH_OK		= 1, /* The attach command succeeded. */
	LTTNG_VIEWER_ATTACH_ALREADY	= 2, /* A viewer is already attached. */
	LTTNG_VIEWER_ATTACH_UNK		= 3, /* The session ID is unknown. */
	LTTNG_VIEWER_ATTACH_NOT_LIVE	= 4, /* The session is not live. */
	LTTNG_VIEWER_ATTACH_SEEK_ERR	= 5, /* Seek error. */
	LTTNG_VIEWER_ATTACH_NO_SESSION	= 6, /* No viewer session created. */
};

enum lttng_viewer_next_index_return_code {
	LTTNG_VIEWER_INDEX_OK		= 1, /* Index is available. */
	LTTNG_VIEWER_INDEX_RETRY	= 2, /* Index not yet available. */
	LTTNG_VIEWER_INDEX_HUP		= 3, /* Index closed (trace destroyed). */
	LTTNG_VIEWER_INDEX_ERR		= 4, /* Unknow error. */
	LTTNG_VIEWER_INDEX_INACTIVE	= 5, /* Inactive stream beacon. */
	LTTNG_VIEWER_INDEX_EOF		= 6, /* End of index file. */
};

enum lttng_viewer_get_packet_return_code {
	LTTNG_VIEWER_GET_PACKET_OK	= 1,
	LTTNG_VIEWER_GET_PACKET_RETRY	= 2,
	LTTNG_VIEWER_GET_PACKET_ERR	= 3,
	LTTNG_VIEWER_GET_PACKET_EOF	= 4,
};

enum lttng_viewer_get_metadata_return_code {
	LTTNG_VIEWER_METADATA_OK	= 1,
	LTTNG_VIEWER_NO_NEW_METADATA	= 2,
	LTTNG_VIEWER_METADATA_ERR	= 3,
};

enum lttng_viewer_connection_type {
	LTTNG_VIEWER_CLIENT_COMMAND		= 1,
	LTTNG_VIEWER_CLIENT_NOTIFICATION	= 2,
};

enum lttng_viewer_seek {
	/* Receive the trace packets from the beginning. */
	LTTNG_VIEWER_SEEK_BEGINNING	= 1,
	/* Receive the trace packets from now. */
	LTTNG_VIEWER_SEEK_LAST		= 2,
};

enum lttng_viewer_new_streams_return_code {
	LTTNG_VIEWER_NEW_STREAMS_OK           = 1, /* If new streams are being sent. */
	LTTNG_VIEWER_NEW_STREAMS_NO_NEW       = 2, /* If no new streams are available. */
	LTTNG_VIEWER_NEW_STREAMS_ERR          = 3, /* Error. */
	LTTNG_VIEWER_NEW_STREAMS_HUP          = 4, /* Session closed. */
};

enum lttng_viewer_create_session_return_code {
	LTTNG_VIEWER_CREATE_SESSION_OK		= 1,
	LTTNG_VIEWER_CREATE_SESSION_ERR		= 2,
};

enum lttng_viewer_detach_session_return_code {
	LTTNG_VIEWER_DETACH_SESSION_OK          = 1,
	LTTNG_VIEWER_DETACH_SESSION_UNK		= 2,
	LTTNG_VIEWER_DETACH_SESSION_ERR         = 3,
};

struct lttng_viewer_session {
	uint64_t id;
	uint32_t live_timer;
	uint32_t clients;
	uint32_t streams;
	char hostname[LTTNG_VIEWER_HOST_NAME_MAX];
	char session_name[LTTNG_VIEWER_NAME_MAX];
} LTTNG_PACKED;

struct lttng_viewer_stream {
	uint64_t id;
	uint64_t ctf_trace_id;
	uint32_t metadata_flag;
	char path_name[LTTNG_VIEWER_PATH_MAX];
	char channel_name[LTTNG_VIEWER_NAME_MAX];
} LTTNG_PACKED;

struct lttng_viewer_cmd {
	uint64_t data_size;	/* data size following this header */
	uint32_t cmd;		/* enum lttcomm_relayd_command */
	uint32_t cmd_version;	/* command version */
} LTTNG_PACKED;

/*
 * LTTNG_VIEWER_CONNECT payload.
 */
struct lttng_viewer_connect {
	/* session ID assigned by the relay for command connections */
	uint64_t viewer_session_id;
	uint32_t major;
	uint32_t minor;
	uint32_t type;		/* enum lttng_viewer_connection_type */
} LTTNG_PACKED;

/*
 * LTTNG_VIEWER_LIST_SESSIONS payload.
 */
struct lttng_viewer_list_sessions {
	uint32_t sessions_count;
	char session_list[];	/* struct lttng_viewer_session */
} LTTNG_PACKED;

/*
 * LTTNG_VIEWER_ATTACH_SESSION payload.
 */
struct lttng_viewer_attach_session_request {
	uint64_t session_id;
	uint64_t offset;	/* unused for now */
	uint32_t seek;		/* enum lttng_viewer_seek */
} LTTNG_PACKED;

struct lttng_viewer_attach_session_response {
	/* enum lttng_viewer_attach_return_code */
	uint32_t status;
	uint32_t streams_count;
	/* struct lttng_viewer_stream */
	char stream_list[];
} LTTNG_PACKED;

/*
 * LTTNG_VIEWER_GET_NEXT_INDEX payload.
 */
struct lttng_viewer_get_next_index {
	uint64_t stream_id;
} __attribute__ ((__packed__));

struct lttng_viewer_index {
	uint64_t offset;
	uint64_t packet_size;
	uint64_t content_size;
	uint64_t timestamp_begin;
	uint64_t timestamp_end;
	uint64_t events_discarded;
	uint64_t stream_id;
	uint32_t status;	/* enum lttng_viewer_next_index_return_code */
	uint32_t flags;		/* LTTNG_VIEWER_FLAG_* */
} __attribute__ ((__packed__));

/*
 * LTTNG_VIEWER_GET_PACKET payload.
 */
struct lttng_viewer_get_packet {
	uint64_t stream_id;
	uint64_t offset;
	uint32_t len;
} LTTNG_PACKED;

struct lttng_viewer_trace_packet {
	uint32_t status;	/* enum lttng_viewer_get_packet_return_code */
	uint32_t len;
	uint32_t flags;		/* LTTNG_VIEWER_FLAG_* */
	char data[];
} LTTNG_PACKED;

/*
 * LTTNG_VIEWER_GET_METADATA payload.
 */
struct lttng_viewer_get_metadata {
	uint64_t stream_id;
} LTTNG_PACKED;

struct lttng_viewer_metadata_packet {
	uint64_t len;
	uint32_t status;	/* enum lttng_viewer_get_metadata_return_code */
	char data[];
} LTTNG_PACKED;

/*
 * LTTNG_VIEWER_GET_NEW_STREAMS payload.
 */
struct lttng_viewer_new_streams_request {
	uint64_t session_id;
} LTTNG_PACKED;

struct lttng_viewer_new_streams_response {
	/* enum lttng_viewer_new_streams_return_code */
	uint32_t status;
	uint32_t streams_count;
	/* struct lttng_viewer_stream */
	char stream_list[];
} LTTNG_PACKED;

struct lttng_viewer_create_session_response {
	/* enum lttng_viewer_create_session_return_code */
	uint32_t status;
} LTTNG_PACKED;

/*
 * LTTNG_VIEWER_DETACH_SESSION payload.
 */
struct lttng_viewer_detach_session_request {
	uint64_t session_id;
} LTTNG_PACKED;

struct lttng_viewer_detach_session_response {
	/* enum lttng_viewer_detach_session_return_code */
	uint32_t status;
} LTTNG_PACKED;

#endif /* LTTNG_VIEWER_ABI_H */
