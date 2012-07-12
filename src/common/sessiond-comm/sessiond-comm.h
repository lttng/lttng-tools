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
#define LTTCOMM_ERR_INDEX(code) (code - LTTCOMM_OK)

enum lttcomm_sessiond_command {
	/* Tracer command */
	LTTNG_ADD_CONTEXT,
	LTTNG_CALIBRATE,
	LTTNG_DISABLE_CHANNEL,
	LTTNG_DISABLE_EVENT,
	LTTNG_DISABLE_ALL_EVENT,
	LTTNG_ENABLE_CHANNEL,
	LTTNG_ENABLE_EVENT,
	LTTNG_ENABLE_ALL_EVENT,
	/* Session daemon command */
	LTTNG_CREATE_SESSION,
	LTTNG_CREATE_SESSION_URI,
	LTTNG_DESTROY_SESSION,
	LTTNG_LIST_CHANNELS,
	LTTNG_LIST_DOMAINS,
	LTTNG_LIST_EVENTS,
	LTTNG_LIST_SESSIONS,
	LTTNG_LIST_TRACEPOINTS,
	LTTNG_REGISTER_CONSUMER,
	LTTNG_START_TRACE,
	LTTNG_STOP_TRACE,
	LTTNG_LIST_TRACEPOINT_FIELDS,

	/* Consumer */
	LTTNG_DISABLE_CONSUMER,
	LTTNG_ENABLE_CONSUMER,
	LTTNG_SET_CONSUMER_URI,
	/* Relay daemon */
	RELAYD_ADD_STREAM,
	RELAYD_CREATE_SESSION,
	RELAYD_START_DATA,
	RELAYD_UPDATE_SYNC_INFO,
	RELAYD_VERSION,
	RELAYD_SEND_METADATA,

	/* Other tracer commands */
	LTTNG_SET_FILTER,
};

/*
 * lttcomm error code.
 */
enum lttcomm_return_code {
	LTTCOMM_OK = 10,				/* Ok */
	LTTCOMM_ERR,					/* Unknown Error */
	LTTCOMM_UND,					/* Undefine command */
	LTTCOMM_NOT_IMPLEMENTED,        /* Command not implemented */
	LTTCOMM_UNKNOWN_DOMAIN,         /* Tracing domain not known */
	LTTCOMM_ALLOC_FAIL,				/* Trace allocation fail */
	LTTCOMM_NO_SESSION,				/* No session found */
	LTTCOMM_CREATE_DIR_FAIL,        /* Create directory fail */
	LTTCOMM_SESSION_FAIL,			/* Create session fail */
	LTTCOMM_START_FAIL,				/* Start tracing fail */
	LTTCOMM_STOP_FAIL,				/* Stop tracing fail */
	LTTCOMM_LIST_FAIL,				/* Listing apps fail */
	LTTCOMM_NO_APPS,				/* No traceable application */
	LTTCOMM_SESS_NOT_FOUND,			/* Session name not found */
	LTTCOMM_NO_TRACE,				/* No trace exist */
	LTTCOMM_FATAL,					/* Session daemon had a fatal error */
	LTTCOMM_NO_TRACEABLE,			/* Error for non traceable app */
	LTTCOMM_SELECT_SESS,			/* Must select a session */
	LTTCOMM_EXIST_SESS,				/* Session name already exist */
	LTTCOMM_NO_EVENT,				/* No event found */
	LTTCOMM_CONNECT_FAIL,           /* Unable to connect to unix socket */
	LTTCOMM_APP_NOT_FOUND,          /* App not found in traceable app list */
	LTTCOMM_EPERM,			/* Permission denied */
	LTTCOMM_KERN_NA,				/* Kernel tracer unavalable */
	LTTCOMM_KERN_VERSION,           /* Kernel tracer version is not compatible */
	LTTCOMM_KERN_EVENT_EXIST,       /* Kernel event already exists */
	LTTCOMM_KERN_SESS_FAIL,			/* Kernel create session failed */
	LTTCOMM_KERN_CHAN_EXIST,        /* Kernel channel already exists */
	LTTCOMM_KERN_CHAN_FAIL,			/* Kernel create channel failed */
	LTTCOMM_KERN_CHAN_NOT_FOUND,	/* Kernel channel not found */
	LTTCOMM_KERN_CHAN_DISABLE_FAIL, /* Kernel disable channel failed */
	LTTCOMM_KERN_CHAN_ENABLE_FAIL,  /* Kernel enable channel failed */
	LTTCOMM_KERN_CONTEXT_FAIL,      /* Kernel add context failed */
	LTTCOMM_KERN_ENABLE_FAIL,		/* Kernel enable event failed */
	LTTCOMM_KERN_DISABLE_FAIL,		/* Kernel disable event failed */
	LTTCOMM_KERN_META_FAIL,			/* Kernel open metadata failed */
	LTTCOMM_KERN_START_FAIL,		/* Kernel start trace failed */
	LTTCOMM_KERN_STOP_FAIL,			/* Kernel stop trace failed */
	LTTCOMM_KERN_CONSUMER_FAIL,		/* Kernel consumer start failed */
	LTTCOMM_KERN_STREAM_FAIL,		/* Kernel create stream failed */
	LTTCOMM_KERN_DIR_FAIL,			/* Kernel trace directory creation failed */
	LTTCOMM_KERN_DIR_EXIST,			/* Kernel trace directory exist */
	LTTCOMM_KERN_NO_SESSION,		/* No kernel session found */
	LTTCOMM_KERN_LIST_FAIL,			/* Kernel listing events failed */
	LTTCOMM_UST_CALIBRATE_FAIL,     /* UST calibration failed */
	LTTCOMM_UST_VERSION,            /* UST tracer version is not compatible */
	LTTCOMM_UST_SESS_FAIL,			/* UST create session failed */
	LTTCOMM_UST_CHAN_EXIST,         /* UST channel already exist */
	LTTCOMM_UST_CHAN_FAIL,			/* UST create channel failed */
	LTTCOMM_UST_CHAN_NOT_FOUND,     /* UST channel not found */
	LTTCOMM_UST_CHAN_DISABLE_FAIL, /* UST disable channel failed */
	LTTCOMM_UST_CHAN_ENABLE_FAIL,  /* UST enable channel failed */
	LTTCOMM_UST_CONTEXT_FAIL,      /* UST add context failed */
	LTTCOMM_UST_ENABLE_FAIL,		/* UST enable event failed */
	LTTCOMM_UST_DISABLE_FAIL,		/* UST disable event failed */
	LTTCOMM_UST_META_FAIL,			/* UST open metadata failed */
	LTTCOMM_UST_START_FAIL,		/* UST start trace failed */
	LTTCOMM_UST_STOP_FAIL,			/* UST stop trace failed */
	LTTCOMM_UST_CONSUMER64_FAIL,		/* 64-bit UST consumer start failed */
	LTTCOMM_UST_CONSUMER32_FAIL,		/* 32-bit UST consumer start failed */
	LTTCOMM_UST_STREAM_FAIL,		/* UST create stream failed */
	LTTCOMM_UST_DIR_FAIL,			/* UST trace directory creation failed */
	LTTCOMM_UST_DIR_EXIST,			/* UST trace directory exist */
	LTTCOMM_UST_NO_SESSION,		/* No UST session found */
	LTTCOMM_UST_LIST_FAIL,			/* UST listing events failed */
	LTTCOMM_UST_EVENT_EXIST,        /* UST event exist */
	LTTCOMM_UST_EVENT_NOT_FOUND,    /* UST event not found */
	LTTCOMM_UST_CONTEXT_EXIST,      /* UST context exist */
	LTTCOMM_UST_CONTEXT_INVAL,      /* UST context invalid */
	LTTCOMM_NEED_ROOT_SESSIOND,		/* root sessiond is needed */
	LTTCOMM_TRACE_ALREADY_STARTED,  /* Tracing already started */
	LTTCOMM_TRACE_ALREADY_STOPPED,  /* Tracing already stopped */
	LTTCOMM_KERN_EVENT_ENOSYS,      /* Kernel event type not supported */

	CONSUMERD_COMMAND_SOCK_READY,		/* when consumerd command socket ready */
	CONSUMERD_SUCCESS_RECV_FD,		/* success on receiving fds */
	CONSUMERD_ERROR_RECV_FD,		/* error on receiving fds */
	CONSUMERD_ERROR_RECV_CMD,		/* error on receiving command */
	CONSUMERD_POLL_ERROR,			/* Error in polling thread in kconsumerd */
	CONSUMERD_POLL_NVAL,			/* Poll on closed fd */
	CONSUMERD_POLL_HUP,			/* All fds have hungup */
	CONSUMERD_EXIT_SUCCESS,			/* kconsumerd exiting normally */
	CONSUMERD_EXIT_FAILURE,			/* kconsumerd exiting on error */
	CONSUMERD_OUTFD_ERROR,			/* error opening the tracefile */
	CONSUMERD_SPLICE_EBADF,			/* EBADF from splice(2) */
	CONSUMERD_SPLICE_EINVAL,		/* EINVAL from splice(2) */
	CONSUMERD_SPLICE_ENOMEM,		/* ENOMEM from splice(2) */
	CONSUMERD_SPLICE_ESPIPE,		/* ESPIPE from splice(2) */
	LTTCOMM_INVALID,			/* Invalid parameter */
	LTTCOMM_NO_USTCONSUMERD,        /* No UST consumer detected */
	LTTCOMM_NO_KERNCONSUMERD,       /* No Kernel consumer detected */
	LTTCOMM_EVENT_EXIST_LOGLEVEL,   /* Event already enabled with different loglevel */
	LTTCOMM_URI_DATA_MISS,          /* Missing network data URI */
	LTTCOMM_URI_CTRL_MISS,          /* Missing network control URI */
	LTTCOMM_ENABLE_CONSUMER_FAIL,   /* Enabling consumer failed */
	LTTCOMM_RELAYD_SESSION_FAIL,    /* lttng-relayd create session failed */
	LTTCOMM_RELAYD_VERSION_FAIL,    /* lttng-relayd not compatible */
	LTTCOMM_FILTER_INVAL,		/* Invalid filter bytecode */
	LTTCOMM_FILTER_NOMEM,		/* Lack of memory for filter bytecode */
	LTTCOMM_FILTER_EXIST,		/* Filter already exist */

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
	LTTCOMM_INET      = 1,
	LTTCOMM_INET6     = 2,
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
			char channel_name[NAME_MAX];
			char name[NAME_MAX];
		} disable;
		/* Event data */
		struct {
			char channel_name[NAME_MAX];
			struct lttng_event event;
		} enable;
		/* Create channel */
		struct {
			struct lttng_channel chan;
		} channel;
		/* Context */
		struct {
			char channel_name[NAME_MAX];
			char event_name[NAME_MAX];
			struct lttng_event_context ctx;
		} context;
		/* Use by register_consumer */
		struct {
			char path[PATH_MAX];
		} reg;
		/* List */
		struct {
			char channel_name[NAME_MAX];
		} list;
		struct lttng_calibrate calibrate;
		/* Used by the set_consumer_uri call */
		struct lttng_uri uri;
		struct {
			uint32_t enable_consumer;
			struct lttng_uri ctrl_uri;
			struct lttng_uri data_uri;
		} create_uri;
		struct {
			char channel_name[NAME_MAX];
			char event_name[NAME_MAX];
			/* Length of following bytecode */
			uint32_t bytecode_len;
		} filter;
	} u;
};

#define LTTNG_FILTER_MAX_LEN	65336

/*
 * Filter bytecode data. The reloc table is located at the end of the
 * bytecode. It is made of tuples: (uint16_t, var. len. string). It
 * starts at reloc_table_offset.
 */
struct lttng_filter_bytecode {
	uint16_t len;	/* len of data */
	uint16_t reloc_table_offset;
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
			char name[LTTNG_SYMBOL_NAME_LEN];  /* Name string of the stream */
		} stream;
		struct {
			int net_index;
			enum lttng_stream_type type;
			/* Open socket to the relayd */
			struct lttcomm_sock sock;
		} relayd_sock;
	} u;
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
