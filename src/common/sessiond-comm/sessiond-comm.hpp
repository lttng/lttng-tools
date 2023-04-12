/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/*
 * This header is meant for liblttng and libust internal use ONLY. These
 * declarations should NOT be considered stable API.
 */

#ifndef _LTTNG_SESSIOND_COMM_H
#define _LTTNG_SESSIOND_COMM_H

#include "inet.hpp"
#include "inet6.hpp"

#include <common/compat/socket.hpp>
#include <common/compiler.hpp>
#include <common/defaults.hpp>
#include <common/macros.hpp>
#include <common/optional.hpp>
#include <common/unix.hpp>
#include <common/uri.hpp>
#include <common/uuid.hpp>

#include <lttng/channel-internal.hpp>
#include <lttng/lttng.h>
#include <lttng/rotate-internal.hpp>
#include <lttng/save-internal.hpp>
#include <lttng/snapshot-internal.hpp>
#include <lttng/trigger/trigger-internal.hpp>

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/un.h>

/* Queue size of listen(2) */
#define LTTNG_SESSIOND_COMM_MAX_LISTEN 64

/* Maximum number of FDs that can be sent over a Unix socket */
#if defined(__linux__)
/* Based on the kernel's SCM_MAX_FD which is 253 since 2.6.38 (255 before) */
#define LTTCOMM_MAX_SEND_FDS 253
#else
#define LTTCOMM_MAX_SEND_FDS 16
#endif

enum lttcomm_sessiond_command {
	LTTCOMM_SESSIOND_COMMAND_MIN,
	LTTCOMM_SESSIOND_COMMAND_ADD_CONTEXT,
	LTTCOMM_SESSIOND_COMMAND_DISABLE_CHANNEL,
	LTTCOMM_SESSIOND_COMMAND_DISABLE_EVENT,
	LTTCOMM_SESSIOND_COMMAND_LIST_SYSCALLS,
	LTTCOMM_SESSIOND_COMMAND_ENABLE_CHANNEL,
	LTTCOMM_SESSIOND_COMMAND_ENABLE_EVENT,
	LTTCOMM_SESSIOND_COMMAND_DESTROY_SESSION,
	LTTCOMM_SESSIOND_COMMAND_LIST_CHANNELS,
	LTTCOMM_SESSIOND_COMMAND_LIST_DOMAINS,
	LTTCOMM_SESSIOND_COMMAND_LIST_EVENTS,
	LTTCOMM_SESSIOND_COMMAND_LIST_SESSIONS,
	LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINTS,
	LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER,
	LTTCOMM_SESSIOND_COMMAND_START_TRACE,
	LTTCOMM_SESSIOND_COMMAND_STOP_TRACE,
	LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINT_FIELDS,
	LTTCOMM_SESSIOND_COMMAND_DISABLE_CONSUMER,
	LTTCOMM_SESSIOND_COMMAND_ENABLE_CONSUMER,
	LTTCOMM_SESSIOND_COMMAND_SET_CONSUMER_URI,
	LTTCOMM_SESSIOND_COMMAND_DATA_PENDING,
	LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_ADD_OUTPUT,
	LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_DEL_OUTPUT,
	LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_LIST_OUTPUT,
	LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_RECORD,
	LTTCOMM_SESSIOND_COMMAND_SAVE_SESSION,
	LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_ADD_INCLUDE_VALUE,
	LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_REMOVE_INCLUDE_VALUE,
	LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_POLICY,
	LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_SET_POLICY,
	LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_INCLUSION_SET,
	LTTCOMM_SESSIOND_COMMAND_SET_SESSION_SHM_PATH,
	LTTCOMM_SESSIOND_COMMAND_REGENERATE_METADATA,
	LTTCOMM_SESSIOND_COMMAND_REGENERATE_STATEDUMP,
	LTTCOMM_SESSIOND_COMMAND_REGISTER_TRIGGER,
	LTTCOMM_SESSIOND_COMMAND_UNREGISTER_TRIGGER,
	LTTCOMM_SESSIOND_COMMAND_ROTATE_SESSION,
	LTTCOMM_SESSIOND_COMMAND_ROTATION_GET_INFO,
	LTTCOMM_SESSIOND_COMMAND_ROTATION_SET_SCHEDULE,
	LTTCOMM_SESSIOND_COMMAND_SESSION_LIST_ROTATION_SCHEDULES,
	LTTCOMM_SESSIOND_COMMAND_CREATE_SESSION_EXT,
	LTTCOMM_SESSIOND_COMMAND_CLEAR_SESSION,
	LTTCOMM_SESSIOND_COMMAND_LIST_TRIGGERS,
	LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY,
	LTTCOMM_SESSIOND_COMMAND_MAX,
};

static inline bool lttcomm_sessiond_command_is_valid(enum lttcomm_sessiond_command cmd)
{
	return cmd > LTTCOMM_SESSIOND_COMMAND_MIN && cmd < LTTCOMM_SESSIOND_COMMAND_MAX;
}

static inline const char *lttcomm_sessiond_command_str(enum lttcomm_sessiond_command cmd)
{
	switch (cmd) {
	case LTTCOMM_SESSIOND_COMMAND_ADD_CONTEXT:
		return "ADD_CONTEXT";
	case LTTCOMM_SESSIOND_COMMAND_DISABLE_CHANNEL:
		return "DISABLE_CHANNEL";
	case LTTCOMM_SESSIOND_COMMAND_DISABLE_EVENT:
		return "DISABLE_EVENT";
	case LTTCOMM_SESSIOND_COMMAND_LIST_SYSCALLS:
		return "LIST_SYSCALLS";
	case LTTCOMM_SESSIOND_COMMAND_ENABLE_CHANNEL:
		return "ENABLE_CHANNEL";
	case LTTCOMM_SESSIOND_COMMAND_ENABLE_EVENT:
		return "ENABLE_EVENT";
	case LTTCOMM_SESSIOND_COMMAND_DESTROY_SESSION:
		return "DESTROY_SESSION";
	case LTTCOMM_SESSIOND_COMMAND_LIST_CHANNELS:
		return "LIST_CHANNELS";
	case LTTCOMM_SESSIOND_COMMAND_LIST_DOMAINS:
		return "LIST_DOMAINS";
	case LTTCOMM_SESSIOND_COMMAND_LIST_EVENTS:
		return "LIST_EVENTS";
	case LTTCOMM_SESSIOND_COMMAND_LIST_SESSIONS:
		return "LIST_SESSIONS";
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINTS:
		return "LIST_TRACEPOINTS";
	case LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER:
		return "REGISTER_CONSUMER";
	case LTTCOMM_SESSIOND_COMMAND_START_TRACE:
		return "START_TRACE";
	case LTTCOMM_SESSIOND_COMMAND_STOP_TRACE:
		return "STOP_TRACE";
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINT_FIELDS:
		return "LIST_TRACEPOINT_FIELDS";
	case LTTCOMM_SESSIOND_COMMAND_DISABLE_CONSUMER:
		return "DISABLE_CONSUMER";
	case LTTCOMM_SESSIOND_COMMAND_ENABLE_CONSUMER:
		return "ENABLE_CONSUMER";
	case LTTCOMM_SESSIOND_COMMAND_SET_CONSUMER_URI:
		return "SET_CONSUMER_URI";
	case LTTCOMM_SESSIOND_COMMAND_DATA_PENDING:
		return "DATA_PENDING";
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_ADD_OUTPUT:
		return "SNAPSHOT_ADD_OUTPUT";
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_DEL_OUTPUT:
		return "SNAPSHOT_DEL_OUTPUT";
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_LIST_OUTPUT:
		return "SNAPSHOT_LIST_OUTPUT";
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_RECORD:
		return "SNAPSHOT_RECORD";
	case LTTCOMM_SESSIOND_COMMAND_SAVE_SESSION:
		return "SAVE_SESSION";
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_ADD_INCLUDE_VALUE:
		return "PROCESS_ATTR_TRACKER_ADD_INCLUDE_VALUE";
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_REMOVE_INCLUDE_VALUE:
		return "PROCESS_ATTR_TRACKER_REMOVE_INCLUDE_VALUE";
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_POLICY:
		return "PROCESS_ATTR_TRACKER_GET_POLICY";
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_SET_POLICY:
		return "PROCESS_ATTR_TRACKER_SET_POLICY";
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_INCLUSION_SET:
		return "PROCESS_ATTR_TRACKER_GET_INCLUSION_SET";
	case LTTCOMM_SESSIOND_COMMAND_SET_SESSION_SHM_PATH:
		return "SET_SESSION_SHM_PATH";
	case LTTCOMM_SESSIOND_COMMAND_REGENERATE_METADATA:
		return "REGENERATE_METADATA";
	case LTTCOMM_SESSIOND_COMMAND_REGENERATE_STATEDUMP:
		return "REGENERATE_STATEDUMP";
	case LTTCOMM_SESSIOND_COMMAND_REGISTER_TRIGGER:
		return "REGISTER_TRIGGER";
	case LTTCOMM_SESSIOND_COMMAND_UNREGISTER_TRIGGER:
		return "UNREGISTER_TRIGGER";
	case LTTCOMM_SESSIOND_COMMAND_ROTATE_SESSION:
		return "ROTATE_SESSION";
	case LTTCOMM_SESSIOND_COMMAND_ROTATION_GET_INFO:
		return "ROTATION_GET_INFO";
	case LTTCOMM_SESSIOND_COMMAND_ROTATION_SET_SCHEDULE:
		return "ROTATION_SET_SCHEDULE";
	case LTTCOMM_SESSIOND_COMMAND_SESSION_LIST_ROTATION_SCHEDULES:
		return "SESSION_LIST_ROTATION_SCHEDULES";
	case LTTCOMM_SESSIOND_COMMAND_CREATE_SESSION_EXT:
		return "CREATE_SESSION_EXT";
	case LTTCOMM_SESSIOND_COMMAND_CLEAR_SESSION:
		return "CLEAR_SESSION";
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRIGGERS:
		return "LIST_TRIGGERS";
	case LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY:
		return "EXECUTE_ERROR_QUERY";
	default:
		abort();
	}
}

enum lttcomm_relayd_command {
	RELAYD_ADD_STREAM = 1,
	RELAYD_CREATE_SESSION = 2,
	RELAYD_START_DATA = 3,
	RELAYD_UPDATE_SYNC_INFO = 4,
	RELAYD_VERSION = 5,
	RELAYD_SEND_METADATA = 6,
	RELAYD_CLOSE_STREAM = 7,
	RELAYD_DATA_PENDING = 8,
	RELAYD_QUIESCENT_CONTROL = 9,
	RELAYD_BEGIN_DATA_PENDING = 10,
	RELAYD_END_DATA_PENDING = 11,
	RELAYD_ADD_INDEX = 12,
	RELAYD_SEND_INDEX = 13,
	RELAYD_CLOSE_INDEX = 14,
	/* Live-reading commands (2.4+). */
	RELAYD_LIST_SESSIONS = 15,
	/* All streams of the channel have been sent to the relayd (2.4+). */
	RELAYD_STREAMS_SENT = 16,
	/* Ask the relay to reset the metadata trace file (2.8+) */
	RELAYD_RESET_METADATA = 17,
	/* Ask the relay to rotate a set of stream files (2.11+) */
	RELAYD_ROTATE_STREAMS = 18,
	/* Ask the relay to create a trace chunk (2.11+) */
	RELAYD_CREATE_TRACE_CHUNK = 19,
	/* Ask the relay to close a trace chunk (2.11+) */
	RELAYD_CLOSE_TRACE_CHUNK = 20,
	/* Ask the relay whether a trace chunk exists (2.11+) */
	RELAYD_TRACE_CHUNK_EXISTS = 21,
	/* Get the current configuration of a relayd peer (2.12+) */
	RELAYD_GET_CONFIGURATION = 22,

	/* Feature branch specific commands start at 10000. */
};

static inline const char *lttcomm_relayd_command_str(lttcomm_relayd_command cmd)
{
	switch (cmd) {
	case RELAYD_ADD_STREAM:
		return "RELAYD_ADD_STREAM";
	case RELAYD_CREATE_SESSION:
		return "RELAYD_CREATE_SESSION";
	case RELAYD_START_DATA:
		return "RELAYD_START_DATA";
	case RELAYD_UPDATE_SYNC_INFO:
		return "RELAYD_UPDATE_SYNC_INFO";
	case RELAYD_VERSION:
		return "RELAYD_VERSION";
	case RELAYD_SEND_METADATA:
		return "RELAYD_SEND_METADATA";
	case RELAYD_CLOSE_STREAM:
		return "RELAYD_CLOSE_STREAM";
	case RELAYD_DATA_PENDING:
		return "RELAYD_DATA_PENDING";
	case RELAYD_QUIESCENT_CONTROL:
		return "RELAYD_QUIESCENT_CONTROL";
	case RELAYD_BEGIN_DATA_PENDING:
		return "RELAYD_BEGIN_DATA_PENDING";
	case RELAYD_END_DATA_PENDING:
		return "RELAYD_END_DATA_PENDING";
	case RELAYD_ADD_INDEX:
		return "RELAYD_ADD_INDEX";
	case RELAYD_SEND_INDEX:
		return "RELAYD_SEND_INDEX";
	case RELAYD_CLOSE_INDEX:
		return "RELAYD_CLOSE_INDEX";
	case RELAYD_LIST_SESSIONS:
		return "RELAYD_LIST_SESSIONS";
	case RELAYD_STREAMS_SENT:
		return "RELAYD_STREAMS_SENT";
	case RELAYD_RESET_METADATA:
		return "RELAYD_RESET_METADATA";
	case RELAYD_ROTATE_STREAMS:
		return "RELAYD_ROTATE_STREAMS";
	case RELAYD_CREATE_TRACE_CHUNK:
		return "RELAYD_CREATE_TRACE_CHUNK";
	case RELAYD_CLOSE_TRACE_CHUNK:
		return "RELAYD_CLOSE_TRACE_CHUNK";
	case RELAYD_TRACE_CHUNK_EXISTS:
		return "RELAYD_TRACE_CHUNK_EXISTS";
	case RELAYD_GET_CONFIGURATION:
		return "RELAYD_GET_CONFIGURATION";
	default:
		abort();
	}
}

/*
 * lttcomm error code.
 */
enum lttcomm_return_code {
	LTTCOMM_CONSUMERD_SUCCESS = 0, /* Everything went fine. */
	/*
	 * Some code paths use -1 to express an error, others
	 * negate this consumer return code. Starting codes at
	 * 100 ensures there is no mix-up between this error value
	 * and legitimate status codes.
	 */
	LTTCOMM_CONSUMERD_COMMAND_SOCK_READY = 100, /* Command socket ready */
	LTTCOMM_CONSUMERD_SUCCESS_RECV_FD, /* Success on receiving fds */
	LTTCOMM_CONSUMERD_ERROR_RECV_FD, /* Error on receiving fds */
	LTTCOMM_CONSUMERD_ERROR_RECV_CMD, /* Error on receiving command */
	LTTCOMM_CONSUMERD_POLL_ERROR, /* Error in polling thread */
	LTTCOMM_CONSUMERD_POLL_NVAL, /* Poll on closed fd */
	LTTCOMM_CONSUMERD_POLL_HUP, /* All fds have hungup */
	LTTCOMM_CONSUMERD_EXIT_SUCCESS, /* Consumerd exiting normally */
	LTTCOMM_CONSUMERD_EXIT_FAILURE, /* Consumerd exiting on error */
	LTTCOMM_CONSUMERD_OUTFD_ERROR, /* Error opening the tracefile */
	LTTCOMM_CONSUMERD_SPLICE_EBADF, /* EBADF from splice(2) */
	LTTCOMM_CONSUMERD_SPLICE_EINVAL, /* EINVAL from splice(2) */
	LTTCOMM_CONSUMERD_SPLICE_ENOMEM, /* ENOMEM from splice(2) */
	LTTCOMM_CONSUMERD_SPLICE_ESPIPE, /* ESPIPE from splice(2) */
	LTTCOMM_CONSUMERD_ENOMEM, /* Consumer is out of memory */
	LTTCOMM_CONSUMERD_ERROR_METADATA, /* Error with metadata. */
	LTTCOMM_CONSUMERD_FATAL, /* Fatal error. */
	LTTCOMM_CONSUMERD_RELAYD_FAIL, /* Error on remote relayd */
	LTTCOMM_CONSUMERD_CHANNEL_FAIL, /* Channel creation failed. */
	LTTCOMM_CONSUMERD_CHAN_NOT_FOUND, /* Channel not found. */
	LTTCOMM_CONSUMERD_ALREADY_SET, /* Resource already set. */
	LTTCOMM_CONSUMERD_ROTATION_FAIL, /* Rotation has failed. */
	LTTCOMM_CONSUMERD_SNAPSHOT_FAILED, /* snapshot has failed. */
	LTTCOMM_CONSUMERD_CREATE_TRACE_CHUNK_FAILED, /* Trace chunk creation failed. */
	LTTCOMM_CONSUMERD_CLOSE_TRACE_CHUNK_FAILED, /* Trace chunk close failed. */
	LTTCOMM_CONSUMERD_INVALID_PARAMETERS, /* Invalid parameters. */
	LTTCOMM_CONSUMERD_TRACE_CHUNK_EXISTS_LOCAL, /* Trace chunk exists on consumer daemon. */
	LTTCOMM_CONSUMERD_TRACE_CHUNK_EXISTS_REMOTE, /* Trace chunk exists on relay daemon. */
	LTTCOMM_CONSUMERD_UNKNOWN_TRACE_CHUNK, /* Unknown trace chunk. */
	LTTCOMM_CONSUMERD_RELAYD_CLEAR_DISALLOWED, /* Relayd does not accept clear command. */
	LTTCOMM_CONSUMERD_UNKNOWN_ERROR, /* Unknown error. */

	/* MUST be last element */
	LTTCOMM_NR, /* Last element */
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
	LTTCOMM_INET = 0,
	LTTCOMM_INET6 = 1,
};

enum lttcomm_metadata_command {
	LTTCOMM_METADATA_REQUEST = 1,
};

/*
 * Commands sent from the consumerd to the sessiond to request if new metadata
 * is available. This message is used to find the per UID _or_ per PID registry
 * for the channel key. For per UID lookup, the triplet
 * bits_per_long/uid/session_id is used. On lookup failure, we search for the
 * per PID registry indexed by session id ignoring the other values.
 */
struct lttcomm_metadata_request_msg {
	uint64_t session_id; /* Tracing session id */
	uint64_t session_id_per_pid; /* Tracing session id for per-pid */
	uint32_t bits_per_long; /* Consumer ABI */
	uint32_t uid;
	uint64_t key; /* Metadata channel key. */
} LTTNG_PACKED;

struct lttcomm_sockaddr {
	enum lttcomm_sock_domain type;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;
};

struct lttcomm_sock {
	int32_t fd;
	enum lttcomm_sock_proto proto;
	struct lttcomm_sockaddr sockaddr;
	const struct lttcomm_proto_ops *ops;
};

/*
 * Relayd sock. Adds the protocol version to use for the communications with
 * the relayd.
 */
struct lttcomm_relayd_sock {
	struct lttcomm_sock sock;
	uint32_t major;
	uint32_t minor;
};

struct lttcomm_net_family {
	int family;
	int (*create)(struct lttcomm_sock *sock, int type, int proto);
};

struct lttcomm_proto_ops {
	int (*bind)(struct lttcomm_sock *sock);
	int (*close)(struct lttcomm_sock *sock);
	int (*connect)(struct lttcomm_sock *sock);
	struct lttcomm_sock *(*accept)(struct lttcomm_sock *sock);
	int (*listen)(struct lttcomm_sock *sock, int backlog);
	ssize_t (*recvmsg)(struct lttcomm_sock *sock, void *buf, size_t len, int flags);
	ssize_t (*sendmsg)(struct lttcomm_sock *sock, const void *buf, size_t len, int flags);
};

struct process_attr_integral_value_comm {
	union {
		int64_t _signed;
		uint64_t _unsigned;
	} u;
} LTTNG_PACKED;

/*
 * Data structure received from lttng client to session daemon.
 */
struct lttcomm_session_msg {
	uint32_t cmd_type; /* enum lttcomm_sessiond_command */
	struct lttng_session session;
	struct lttng_domain domain;
	union {
		/* Event data */
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
			uint32_t length;
		} LTTNG_PACKED enable;
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
			uint32_t length;
		} LTTNG_PACKED disable;
		/* Create channel */
		struct {
			uint32_t length;
		} LTTNG_PACKED channel;
		/* Context */
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
			uint32_t length;
		} LTTNG_PACKED context;
		/* Use by register_consumer */
		struct {
			char path[PATH_MAX];
		} LTTNG_PACKED reg;
		/* List */
		struct {
			char channel_name[LTTNG_SYMBOL_NAME_LEN];
		} LTTNG_PACKED list;
		struct lttng_calibrate calibrate;
		/* Used by the set_consumer_url and used by create_session also call */
		struct {
			/* Number of lttng_uri following */
			uint32_t size;
		} LTTNG_PACKED uri;
		struct {
			struct lttng_snapshot_output output;
		} LTTNG_PACKED snapshot_output;
		struct {
			uint32_t wait;
			struct lttng_snapshot_output output;
		} LTTNG_PACKED snapshot_record;
		struct {
			uint32_t nb_uri;
			unsigned int timer_interval; /* usec */
		} LTTNG_PACKED session_live;
		struct {
			struct lttng_save_session_attr attr;
		} LTTNG_PACKED save_session;
		struct {
			char shm_path[PATH_MAX];
		} LTTNG_PACKED set_shm_path;
		struct {
			/* enum lttng_process_attr */
			int32_t process_attr;
			/* enum lttng_process_attr_value_type */
			int32_t value_type;

			struct process_attr_integral_value_comm integral_value;
			/*
			 * For user/group names, a variable length,
			 * zero-terminated, string of length 'name_len'
			 * (including the terminator) follows.
			 *
			 * integral_value should not be used in those cases.
			 */
			uint32_t name_len;
		} LTTNG_PACKED process_attr_tracker_add_remove_include_value;
		struct {
			/* enum lttng_process_attr */
			int32_t process_attr;
		} LTTNG_PACKED process_attr_tracker_get_inclusion_set;
		struct {
			/* enum lttng_process_attr */
			int32_t process_attr;
		} LTTNG_PACKED process_attr_tracker_get_tracking_policy;
		struct {
			/* enum lttng_process_attr */
			int32_t process_attr;
			/* enum lttng_tracking_policy */
			int32_t tracking_policy;
		} LTTNG_PACKED process_attr_tracker_set_tracking_policy;
		struct {
			uint32_t length;
			uint8_t is_trigger_anonymous;
		} LTTNG_PACKED trigger;
		struct {
			uint32_t length;
		} LTTNG_PACKED error_query;
		struct {
			uint64_t rotation_id;
		} LTTNG_PACKED get_rotation_info;
		struct {
			/* enum lttng_rotation_schedule_type */
			uint8_t type;
			/*
			 * If set == 1, set schedule to value, if set == 0,
			 * clear this schedule type.
			 */
			uint8_t set;
			uint64_t value;
		} LTTNG_PACKED rotation_set_schedule;
		struct {
			/*
			 * Includes the null-terminator.
			 * Must be an absolute path.
			 *
			 * Size bounded by LTTNG_PATH_MAX.
			 */
			uint16_t home_dir_size;
			uint64_t session_descriptor_size;
			/* An lttng_session_descriptor follows. */
		} LTTNG_PACKED create_session;
	} u;
	/* Count of fds sent. */
	uint32_t fd_count;
} LTTNG_PACKED;

#define LTTNG_FILTER_MAX_LEN		 65536
#define LTTNG_SESSION_DESCRIPTOR_MAX_LEN 65536

/*
 * Filter bytecode data. The reloc table is located at the end of the
 * bytecode. It is made of tuples: (uint16_t, var. len. string). It
 * starts at reloc_table_offset.
 */
#define LTTNG_FILTER_PADDING 32
struct lttng_bytecode {
	uint32_t len; /* len of data */
	uint32_t reloc_table_offset;
	uint64_t seqnum;
	char padding[LTTNG_FILTER_PADDING];
	char data[0];
} LTTNG_PACKED;

/*
 * Event exclusion data. At the end of the structure, there will actually
 * by zero or more names, where the actual number of names is given by
 * the 'count' item of the structure.
 */
#define LTTNG_EVENT_EXCLUSION_PADDING 32
struct lttng_event_exclusion {
	uint32_t count;
	char padding[LTTNG_EVENT_EXCLUSION_PADDING];
	char names[LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH][LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

#define LTTNG_EVENT_EXCLUSION_NAME_AT(_exclusion, _i) ((_exclusion)->names[_i])

/*
 * Listing command header.
 */
struct lttcomm_list_command_header {
	/* Number of elements */
	uint32_t count;
} LTTNG_PACKED;

/*
 * Event extended info header. This is the structure preceding each
 * extended info data.
 */
struct lttcomm_event_extended_header {
	/*
	 * Size of filter string immediately following this header.
	 * This size includes the terminal null character.
	 */
	uint32_t filter_len;

	/*
	 * Number of exclusion names, immediately following the filter
	 * string. Each exclusion name has a fixed length of
	 * LTTNG_SYMBOL_NAME_LEN bytes, including the terminal null
	 * character.
	 */
	uint32_t nb_exclusions;

	/*
	 * Size of the event's userspace probe location (if applicable).
	 */
	uint32_t userspace_probe_location_len;
} LTTNG_PACKED;

/*
 * Command header of the reply to an LTTCOMM_SESSIOND_COMMAND_DESTROY_SESSION command.
 */
struct lttcomm_session_destroy_command_header {
	/* enum lttng_session */
	int32_t rotation_state;
};

/*
 * tracker command header.
 */
struct lttcomm_tracker_command_header {
	uint32_t nb_tracker_id;
} LTTNG_PACKED;

/*
 * Data structure for the response from sessiond to the lttng client.
 */
struct lttcomm_lttng_msg {
	uint32_t cmd_type; /* enum lttcomm_sessiond_command */
	uint32_t ret_code; /* enum lttcomm_return_code */
	uint32_t pid; /* pid_t */
	uint32_t cmd_header_size;
	uint32_t data_size;
	uint32_t fd_count;
} LTTNG_PACKED;

struct lttcomm_lttng_output_id {
	uint32_t id;
} LTTNG_PACKED;

/*
 * lttcomm_consumer_msg is the message sent from sessiond to consumerd
 * to either add a channel, add a stream, update a stream, or stop
 * operation.
 */
struct lttcomm_consumer_msg {
	uint32_t cmd_type; /* enum lttng_consumer_command */
	union {
		struct {
			uint64_t channel_key;
			uint64_t session_id;
			/* ID of the session's current trace chunk. */
			LTTNG_OPTIONAL_COMM(uint64_t) LTTNG_PACKED chunk_id;
			char pathname[PATH_MAX];
			uint64_t relayd_id;
			/* nb_init_streams is the number of streams open initially. */
			uint32_t nb_init_streams;
			char name[LTTNG_SYMBOL_NAME_LEN];
			/* Use splice or mmap to consume this fd */
			enum lttng_event_output output;
			int type; /* Per cpu or metadata. */
			uint64_t tracefile_size; /* bytes */
			uint32_t tracefile_count; /* number of tracefiles */
			/* If the channel's streams have to be monitored or not. */
			uint32_t monitor;
			/* timer to check the streams usage in live mode (usec). */
			unsigned int live_timer_interval;
			/* is part of a live session */
			uint8_t is_live;
			/* timer to sample a channel's positions (usec). */
			unsigned int monitor_timer_interval;
		} LTTNG_PACKED channel; /* Only used by Kernel. */
		struct {
			uint64_t stream_key;
			uint64_t channel_key;
			int32_t cpu; /* On which CPU this stream is assigned. */
			/* Tells the consumer if the stream should be or not monitored. */
			uint32_t no_monitor;
		} LTTNG_PACKED stream; /* Only used by Kernel. */
		struct {
			uint64_t net_index;
			enum lttng_stream_type type;
			uint32_t major;
			uint32_t minor;
			uint8_t relayd_socket_protocol;
			/* Tracing session id associated to the relayd. */
			uint64_t session_id;
			/* Relayd session id, only used with control socket. */
			uint64_t relayd_session_id;
		} LTTNG_PACKED relayd_sock;
		struct {
			uint64_t net_seq_idx;
		} LTTNG_PACKED destroy_relayd;
		struct {
			uint64_t session_id;
		} LTTNG_PACKED data_pending;
		struct {
			uint64_t subbuf_size; /* bytes */
			uint64_t num_subbuf; /* power of 2 */
			int32_t overwrite; /* 1: overwrite, 0: discard */
			uint32_t switch_timer_interval; /* usec */
			uint32_t read_timer_interval; /* usec */
			unsigned int live_timer_interval; /* usec */
			uint8_t is_live; /* is part of a live session */
			uint32_t monitor_timer_interval; /* usec */
			int32_t output; /* splice, mmap */
			int32_t type; /* metadata or per_cpu */
			uint64_t session_id; /* Tracing session id */
			char pathname[PATH_MAX]; /* Channel file path. */
			char name[LTTNG_SYMBOL_NAME_LEN]; /* Channel name. */
			/* Credentials used to open the UST buffer shared mappings. */
			struct {
				uint32_t uid;
				uint32_t gid;
			} LTTNG_PACKED buffer_credentials;
			uint64_t relayd_id; /* Relayd id if apply. */
			uint64_t key; /* Unique channel key. */
			/* ID of the session's current trace chunk. */
			LTTNG_OPTIONAL_COMM(uint64_t) LTTNG_PACKED chunk_id;
			unsigned char uuid[LTTNG_UUID_LEN]; /* uuid for ust tracer. */
			uint32_t chan_id; /* Channel ID on the tracer side. */
			uint64_t tracefile_size; /* bytes */
			uint32_t tracefile_count; /* number of tracefiles */
			uint64_t session_id_per_pid; /* Per-pid session ID. */
			/* Tells the consumer if the stream should be or not monitored. */
			uint32_t monitor;
			/*
			 * For UST per UID buffers, this is the application UID of the
			 * channel.  This can be different from the user UID requesting the
			 * channel creation and used for the rights on the stream file
			 * because the application can be in the tracing for instance.
			 */
			uint32_t ust_app_uid;
			int64_t blocking_timeout;
			char root_shm_path[PATH_MAX];
			char shm_path[PATH_MAX];
		} LTTNG_PACKED ask_channel;
		struct {
			uint64_t key;
		} LTTNG_PACKED get_channel;
		struct {
			uint64_t key;
		} LTTNG_PACKED destroy_channel;
		struct {
			uint64_t key; /* Metadata channel key. */
			uint64_t target_offset; /* Offset in the consumer */
			uint64_t len; /* Length of metadata to be received. */
			uint64_t version; /* Version of the metadata. */
		} LTTNG_PACKED push_metadata;
		struct {
			uint64_t key; /* Metadata channel key. */
		} LTTNG_PACKED close_metadata;
		struct {
			uint64_t key; /* Metadata channel key. */
		} LTTNG_PACKED setup_metadata;
		struct {
			uint64_t key; /* Channel key. */
		} LTTNG_PACKED flush_channel;
		struct {
			uint64_t key; /* Channel key. */
		} LTTNG_PACKED clear_quiescent_channel;
		struct {
			char pathname[PATH_MAX];
			/* Indicate if the snapshot goes on the relayd or locally. */
			uint32_t use_relayd;
			uint32_t metadata; /* This a metadata snapshot. */
			uint64_t relayd_id; /* Relayd id if apply. */
			uint64_t key;
			uint64_t nb_packets_per_stream;
		} LTTNG_PACKED snapshot_channel;
		struct {
			uint64_t channel_key;
			uint64_t net_seq_idx;
		} LTTNG_PACKED sent_streams;
		struct {
			uint64_t session_id;
			uint64_t channel_key;
		} LTTNG_PACKED discarded_events;
		struct {
			uint64_t session_id;
			uint64_t channel_key;
		} LTTNG_PACKED lost_packets;
		struct {
			uint64_t session_id;
		} LTTNG_PACKED regenerate_metadata;
		struct {
			uint32_t metadata; /* This is a metadata channel. */
			uint64_t relayd_id; /* Relayd id if apply. */
			uint64_t key;
		} LTTNG_PACKED rotate_channel;
		struct {
			uint64_t session_id;
			uint64_t chunk_id;
		} LTTNG_PACKED check_rotation_pending_local;
		struct {
			uint64_t relayd_id;
			uint64_t session_id;
			uint64_t chunk_id;
		} LTTNG_PACKED check_rotation_pending_relay;
		struct {
			/*
			 * Relayd id, if applicable (remote).
			 *
			 * A directory file descriptor referring to the chunk's
			 * output folder is transmitted if the chunk is local
			 * (relayd_id unset).
			 *
			 * `override_name` is left NULL (all-zeroes) if the
			 * chunk's name is not overridden.
			 */
			LTTNG_OPTIONAL_COMM(uint64_t) LTTNG_PACKED relayd_id;
			char override_name[LTTNG_NAME_MAX];
			uint64_t session_id;
			uint64_t chunk_id;
			uint64_t creation_timestamp;
			LTTNG_OPTIONAL_COMM(struct {
				uint32_t uid;
				uint32_t gid;
			} LTTNG_PACKED)
			LTTNG_PACKED credentials;
		} LTTNG_PACKED create_trace_chunk;
		struct {
			LTTNG_OPTIONAL_COMM(uint64_t) LTTNG_PACKED relayd_id;
			uint64_t session_id;
			uint64_t chunk_id;
			uint64_t close_timestamp;
			/* enum lttng_trace_chunk_command_type */
			LTTNG_OPTIONAL_COMM(uint32_t) LTTNG_PACKED close_command;
		} LTTNG_PACKED close_trace_chunk;
		struct {
			LTTNG_OPTIONAL_COMM(uint64_t) LTTNG_PACKED relayd_id;
			uint64_t session_id;
			uint64_t chunk_id;
		} LTTNG_PACKED trace_chunk_exists;
		struct {
			uint8_t sessiond_uuid[LTTNG_UUID_LEN];
		} LTTNG_PACKED init;
		struct {
			uint64_t key;
		} LTTNG_PACKED clear_channel;
		struct {
			uint64_t key;
		} LTTNG_PACKED open_channel_packets;
	} u;
} LTTNG_PACKED;

/*
 * Channel monitoring message returned to the session daemon on every
 * monitor timer expiration.
 */
struct lttcomm_consumer_channel_monitor_msg {
	/* Key of the sampled channel. */
	uint64_t key;
	/* Id of the sampled channel's session. */
	uint64_t session_id;
	/*
	 * Lowest and highest usage (bytes) at the moment the sample was taken.
	 */
	uint64_t lowest, highest;
	/*
	 * Sum of all the consumed positions for a channel.
	 */
	uint64_t consumed_since_last_sample;
} LTTNG_PACKED;

/*
 * Status message returned to the sessiond after a received command.
 */
struct lttcomm_consumer_status_msg {
	enum lttcomm_return_code ret_code;
} LTTNG_PACKED;

struct lttcomm_consumer_status_channel {
	enum lttcomm_return_code ret_code;
	uint64_t key;
	unsigned int stream_count;
} LTTNG_PACKED;

struct lttcomm_consumer_close_trace_chunk_reply {
	enum lttcomm_return_code ret_code;
	uint32_t path_length;
	char path[];
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
		struct lttng_ust_abi_channel channel;
		struct lttng_ust_abi_stream stream;
		struct lttng_ust_abi_event event;
		struct lttng_ust_abi_context context;
		struct lttng_ust_abi_tracer_version version;
	} u;
} LTTNG_PACKED;

/*
 * Data structure for the response from UST to the session daemon.
 * cmd_type is sent back in the reply for validation.
 */
struct lttcomm_ust_reply {
	uint32_t handle;
	uint32_t cmd;
	uint32_t ret_code; /* enum lttcomm_return_code */
	uint32_t ret_val; /* return value */
	union {
		struct {
			uint64_t memory_map_size;
		} LTTNG_PACKED channel;
		struct {
			uint64_t memory_map_size;
		} LTTNG_PACKED stream;
		struct lttng_ust_abi_tracer_version version;
	} u;
} LTTNG_PACKED;

#endif /* HAVE_LIBLTTNG_UST_CTL */

const char *lttcomm_get_readable_code(enum lttcomm_return_code code);

int lttcomm_init_inet_sockaddr(struct lttcomm_sockaddr *sockaddr,
			       const char *ip,
			       unsigned int port);
int lttcomm_init_inet6_sockaddr(struct lttcomm_sockaddr *sockaddr,
				const char *ip,
				unsigned int port);

struct lttcomm_sock *lttcomm_alloc_sock(enum lttcomm_sock_proto proto);
int lttcomm_populate_sock_from_open_socket(struct lttcomm_sock *sock,
					   int fd,
					   enum lttcomm_sock_proto protocol);
int lttcomm_create_sock(struct lttcomm_sock *sock);
struct lttcomm_sock *lttcomm_alloc_sock_from_uri(struct lttng_uri *uri);
void lttcomm_destroy_sock(struct lttcomm_sock *sock);
struct lttcomm_sock *lttcomm_alloc_copy_sock(struct lttcomm_sock *src);
void lttcomm_copy_sock(struct lttcomm_sock *dst, struct lttcomm_sock *src);

/* Relayd socket object. */
struct lttcomm_relayd_sock *
lttcomm_alloc_relayd_sock(struct lttng_uri *uri, uint32_t major, uint32_t minor);

int lttcomm_setsockopt_rcv_timeout(int sock, unsigned int msec);
int lttcomm_setsockopt_snd_timeout(int sock, unsigned int msec);

int lttcomm_sock_get_port(const struct lttcomm_sock *sock, uint16_t *port);
/*
 * Set a port to an lttcomm_sock. This will have no effect is the socket is
 * already bound.
 */
int lttcomm_sock_set_port(struct lttcomm_sock *sock, uint16_t port);

void lttcomm_init();
/* Get network timeout, in milliseconds */
unsigned long lttcomm_get_network_timeout();

#endif /* _LTTNG_SESSIOND_COMM_H */
