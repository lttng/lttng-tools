/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This header is meant for liblttng and libust internal use ONLY. These
 * declarations should NOT be considered stable API.
 */

#ifndef _LTTNG_SESSIOND_COMM_H
#define _LTTNG_SESSIOND_COMM_H

#define _GNU_SOURCE
#include <limits.h>
#include <lttng/lttng.h>
#include <common/compat/socket.h>
#include <common/uri.h>
#include <common/defaults.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "inet.h"
#include "inet6.h"
#include "unix.h"

/* Queue size of listen(2) */
#define LTTNG_SESSIOND_COMM_MAX_LISTEN 64

/* Maximum number of FDs that can be sent over a Unix socket */
#define LTTCOMM_MAX_SEND_FDS           4

/*
 * Get the error code index from 0 since LTTCOMM_OK start at 1000
 */
#define LTTCOMM_ERR_INDEX(code) (code - LTTCOMM_CONSUMERD_COMMAND_SOCK_READY)

enum lttcomm_sessiond_command {
	/* Tracer command */
	LTTNG_ADD_CONTEXT					= 1,
	LTTNG_CALIBRATE						= 2,
	LTTNG_DISABLE_CHANNEL				= 3,
	LTTNG_DISABLE_EVENT					= 4,
	LTTNG_DISABLE_ALL_EVENT				= 5,
	LTTNG_ENABLE_CHANNEL				= 6,
	LTTNG_ENABLE_EVENT					= 7,
	LTTNG_ENABLE_ALL_EVENT				= 8,
	/* Session daemon command */
	LTTNG_CREATE_SESSION				= 9,
	LTTNG_DESTROY_SESSION				= 10,
	LTTNG_LIST_CHANNELS                 = 11,
	LTTNG_LIST_DOMAINS                  = 12,
	LTTNG_LIST_EVENTS                   = 13,
	LTTNG_LIST_SESSIONS                 = 14,
	LTTNG_LIST_TRACEPOINTS              = 15,
	LTTNG_REGISTER_CONSUMER             = 16,
	LTTNG_START_TRACE                   = 17,
	LTTNG_STOP_TRACE                    = 18,
	LTTNG_LIST_TRACEPOINT_FIELDS        = 19,

	/* Consumer */
	LTTNG_DISABLE_CONSUMER              = 20,
	LTTNG_ENABLE_CONSUMER               = 21,
	LTTNG_SET_CONSUMER_URI              = 22,
	/* Relay daemon */
	RELAYD_ADD_STREAM                   = 23,
	RELAYD_CREATE_SESSION               = 24,
	RELAYD_START_DATA                   = 25,
	RELAYD_UPDATE_SYNC_INFO             = 26,
	RELAYD_VERSION                      = 27,
	RELAYD_SEND_METADATA                = 28,
	RELAYD_CLOSE_STREAM                 = 29,
	RELAYD_DATA_PENDING                 = 30,
	RELAYD_QUIESCENT_CONTROL            = 31,
	LTTNG_ENABLE_EVENT_WITH_FILTER      = 32,
	LTTNG_HEALTH_CHECK                  = 33,
	LTTNG_DATA_PENDING                  = 34,
};

/*
 * lttcomm error code.
 */
enum lttcomm_return_code {
	LTTCOMM_CONSUMERD_COMMAND_SOCK_READY = 1,   /* Command socket ready */
	LTTCOMM_CONSUMERD_SUCCESS_RECV_FD,          /* Success on receiving fds */
	LTTCOMM_CONSUMERD_ERROR_RECV_FD,            /* Error on receiving fds */
	LTTCOMM_CONSUMERD_ERROR_RECV_CMD,           /* Error on receiving command */
	LTTCOMM_CONSUMERD_POLL_ERROR,               /* Error in polling thread */
	LTTCOMM_CONSUMERD_POLL_NVAL,                /* Poll on closed fd */
	LTTCOMM_CONSUMERD_POLL_HUP,                 /* All fds have hungup */
	LTTCOMM_CONSUMERD_EXIT_SUCCESS,             /* Consumerd exiting normally */
	LTTCOMM_CONSUMERD_EXIT_FAILURE,             /* Consumerd exiting on error */
	LTTCOMM_CONSUMERD_OUTFD_ERROR,              /* Error opening the tracefile */
	LTTCOMM_CONSUMERD_SPLICE_EBADF,             /* EBADF from splice(2) */
	LTTCOMM_CONSUMERD_SPLICE_EINVAL,            /* EINVAL from splice(2) */
	LTTCOMM_CONSUMERD_SPLICE_ENOMEM,            /* ENOMEM from splice(2) */
	LTTCOMM_CONSUMERD_SPLICE_ESPIPE,            /* ESPIPE from splice(2) */

	/* MUST be last element */
	LTTCOMM_NR,						/* Last element */
};

/* lttng socket protocol. */
enum lttcomm_sock_proto {
	LTTCOMM_SOCK_UDP,
	LTTCOMM_SOCK_TCP,
};

/*
 * Index in the net_families array below. Please keep in sync!
 */
enum lttcomm_sock_domain {
	LTTCOMM_INET      = 0,
	LTTCOMM_INET6     = 1,
};

struct lttcomm_sockaddr {
	enum lttcomm_sock_domain type;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;
};

struct lttcomm_sock {
	int fd;
	enum lttcomm_sock_proto proto;
	struct lttcomm_sockaddr sockaddr;
	const struct lttcomm_proto_ops *ops;
};

struct lttcomm_net_family {
	int family;
	int (*create) (struct lttcomm_sock *sock, int type, int proto);
};

struct lttcomm_proto_ops {
	int (*bind) (struct lttcomm_sock *sock);
	int (*close) (struct lttcomm_sock *sock);
	int (*connect) (struct lttcomm_sock *sock);
	struct lttcomm_sock *(*accept) (struct lttcomm_sock *sock);
	int (*listen) (struct lttcomm_sock *sock, int backlog);
	ssize_t (*recvmsg) (struct lttcomm_sock *sock, void *buf, size_t len,
			int flags);
	ssize_t (*sendmsg) (struct lttcomm_sock *sock, void *buf, size_t len,
			int flags);
};

/*
 * Data structure received from lttng client to session daemon.
 */
struct lttcomm_session_msg {
	uint32_t cmd_type;    /* enum lttcomm_sessiond_command */
	struct lttng_session session;
	struct lttng_domain domain;
	union {
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
			char name[NAME_MAX];
		} disable;
		/* Event data */
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
			struct lttng_event event;
			/* Length of following bytecode for filter. */
			uint32_t bytecode_len;
		} enable;
		/* Create channel */
		struct {
			struct lttng_channel chan;
		} channel;
		/* Context */
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
			struct lttng_event_context ctx;
		} context;
		/* Use by register_consumer */
		struct {
			char path[PATH_MAX];
		} reg;
		/* List */
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
		} list;
		struct lttng_calibrate calibrate;
		/* Used by the set_consumer_url and used by create_session also call */
		struct {
			/* Number of lttng_uri following */
			uint32_t size;
		} uri;
	} u;
};

#define LTTNG_FILTER_MAX_LEN	65536

/*
 * Filter bytecode data. The reloc table is located at the end of the
 * bytecode. It is made of tuples: (uint16_t, var. len. string). It
 * starts at reloc_table_offset.
 */
#define LTTNG_FILTER_PADDING	32
struct lttng_filter_bytecode {
	uint32_t len;	/* len of data */
	uint32_t reloc_table_offset;
	uint64_t seqnum;
	char padding[LTTNG_FILTER_PADDING];
	char data[0];
};

/*
 * Data structure for the response from sessiond to the lttng client.
 */
struct lttcomm_lttng_msg {
	uint32_t cmd_type;   /* enum lttcomm_sessiond_command */
	uint32_t ret_code;   /* enum lttcomm_return_code */
	uint32_t pid;        /* pid_t */
	uint32_t data_size;
	/* Contains: trace_name + data */
	char payload[];
};

struct lttcomm_health_msg {
	uint32_t component;
	uint32_t cmd;
};

struct lttcomm_health_data {
	uint32_t ret_code;
};

/*
 * lttcomm_consumer_msg is the message sent from sessiond to consumerd
 * to either add a channel, add a stream, update a stream, or stop
 * operation.
 */
struct lttcomm_consumer_msg {
	uint32_t cmd_type;	/* enum consumerd_command */
	union {
		struct {
			int channel_key;
			uint64_t max_sb_size; /* the subbuffer size for this channel */
			/* shm_fd and wait_fd are sent as ancillary data */
			uint64_t mmap_len;
			/* nb_init_streams is the number of streams open initially. */
			unsigned int nb_init_streams;
			char name[LTTNG_SYMBOL_NAME_LEN];
		} channel;
		struct {
			int channel_key;
			int stream_key;
			/* shm_fd and wait_fd are sent as ancillary data */
			uint32_t state;    /* enum lttcomm_consumer_fd_state */
			enum lttng_event_output output; /* use splice or mmap to consume this fd */
			uint64_t mmap_len;
			uid_t uid;         /* User ID owning the session */
			gid_t gid;         /* Group ID owning the session */
			char path_name[PATH_MAX];
			int net_index;
			unsigned int metadata_flag;
			char name[DEFAULT_STREAM_NAME_LEN];  /* Name string of the stream */
			uint64_t session_id;   /* Tracing session id of the stream */
		} stream;
		struct {
			int net_index;
			enum lttng_stream_type type;
			/* Open socket to the relayd */
			struct lttcomm_sock sock;
		} relayd_sock;
		struct {
			uint64_t net_seq_idx;
		} destroy_relayd;
		struct {
			uint64_t session_id;
		} data_pending;
	} u;
};

/*
 * Status message returned to the sessiond after a received command.
 */
struct lttcomm_consumer_status_msg {
	enum lttng_error_code ret_code;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

#include <lttng/ust-abi.h>

/*
 * Data structure for the commands sent from sessiond to UST.
 */
struct lttcomm_ust_msg {
	uint32_t handle;
	uint32_t cmd;
	union {
		struct lttng_ust_channel channel;
		struct lttng_ust_stream stream;
		struct lttng_ust_event event;
		struct lttng_ust_context context;
		struct lttng_ust_tracer_version version;
	} u;
};

/*
 * Data structure for the response from UST to the session daemon.
 * cmd_type is sent back in the reply for validation.
 */
struct lttcomm_ust_reply {
	uint32_t handle;
	uint32_t cmd;
	uint32_t ret_code;	/* enum lttcomm_return_code */
	uint32_t ret_val;	/* return value */
	union {
		struct {
			uint64_t memory_map_size;
		} channel;
		struct {
			uint64_t memory_map_size;
		} stream;
		struct lttng_ust_tracer_version version;
	} u;
};

#endif /* HAVE_LIBLTTNG_UST_CTL */

extern const char *lttcomm_get_readable_code(enum lttcomm_return_code code);

extern int lttcomm_init_inet_sockaddr(struct lttcomm_sockaddr *sockaddr,
		const char *ip, unsigned int port);
extern int lttcomm_init_inet6_sockaddr(struct lttcomm_sockaddr *sockaddr,
		const char *ip, unsigned int port);

extern struct lttcomm_sock *lttcomm_alloc_sock(enum lttcomm_sock_proto proto);
extern int lttcomm_create_sock(struct lttcomm_sock *sock);
extern struct lttcomm_sock *lttcomm_alloc_sock_from_uri(struct lttng_uri *uri);
extern void lttcomm_destroy_sock(struct lttcomm_sock *sock);
extern struct lttcomm_sock *lttcomm_alloc_copy_sock(struct lttcomm_sock *src);
extern void lttcomm_copy_sock(struct lttcomm_sock *dst,
		struct lttcomm_sock *src);

#endif	/* _LTTNG_SESSIOND_COMM_H */
