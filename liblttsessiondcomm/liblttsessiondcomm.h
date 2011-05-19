/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Julien Desfossez <julien.desfossez@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 */

#ifndef _LIBLTTSESSIONDCOMM_H
#define _LIBLTTSESSIONDCOMM_H

#include <limits.h>
#include <uuid/uuid.h>

#include "lttng-share.h"

#define LTTNG_RUNDIR						"/var/run/lttng"

/* Default unix socket path */
#define DEFAULT_GLOBAL_CLIENT_UNIX_SOCK		LTTNG_RUNDIR "/client-ltt-sessiond"
#define DEFAULT_GLOBAL_APPS_UNIX_SOCK		LTTNG_RUNDIR "/apps-ltt-sessiond"
#define DEFAULT_HOME_APPS_UNIX_SOCK			"%s/.apps-ltt-sessiond"
#define DEFAULT_HOME_CLIENT_UNIX_SOCK		"%s/.client-ltt-sessiond"

/* Kernel consumer path */
#define KCONSUMERD_PATH						LTTNG_RUNDIR "/kconsumerd"
#define KCONSUMERD_CMD_SOCK_PATH			KCONSUMERD_PATH "/command"
#define KCONSUMERD_ERR_SOCK_PATH			KCONSUMERD_PATH "/error"

/* Queue size of listen(2) */
#define MAX_LISTEN 10

/* Get the error code index from 0 since
 * LTTCOMM_OK start at 1000
 */
#define LTTCOMM_ERR_INDEX(code) (code - LTTCOMM_OK)

enum lttcomm_sessiond_command {
	KERNEL_CREATE_CHANNEL,
	KERNEL_CREATE_SESSION,
	KERNEL_DISABLE_EVENT,
	KERNEL_ENABLE_EVENT,
	KERNEL_START_TRACE,
	KERNEL_STOP_TRACE,
	LTTNG_CREATE_SESSION,
	LTTNG_DESTROY_SESSION,
	LTTNG_FORCE_SUBBUF_SWITCH,
	LTTNG_GET_ALL_SESSION,
	LTTNG_GET_SOCK_PATH,
	LTTNG_GET_SUBBUF_NUM_SIZE,
	LTTNG_LIST_MARKERS,
	LTTNG_LIST_SESSIONS,
	LTTNG_LIST_TRACES,
	LTTNG_LIST_TRACE_EVENTS,
	LTTNG_SETUP_TRACE,
	LTTNG_SET_SOCK_PATH,
	LTTNG_SET_SUBBUF_NUM,
	LTTNG_SET_SUBBUF_SIZE,
	UST_ALLOC_TRACE,
	UST_CREATE_TRACE,
	UST_DESTROY_TRACE,
	UST_DISABLE_MARKER,
	UST_ENABLE_MARKER,
	UST_LIST_APPS,
	UST_START_TRACE,
	UST_STOP_TRACE,
};

/*
 * lttcomm error code.
 */
enum lttcomm_return_code {
	LTTCOMM_OK = 1000,				/* Ok */
	LTTCOMM_ERR,					/* Unknown Error */
	LTTCOMM_UND,					/* Undefine command */
	LTTCOMM_ALLOC_FAIL,				/* Trace allocation fail */
	LTTCOMM_NO_SESSION,				/* No session found */
	LTTCOMM_CREATE_FAIL,			/* Create trace fail */
	LTTCOMM_SESSION_FAIL,			/* Create session fail */
	LTTCOMM_START_FAIL,				/* Start tracing fail */
	LTTCOMM_STOP_FAIL,				/* Stop tracing fail */
	LTTCOMM_LIST_FAIL,				/* Listing apps fail */
	LTTCOMM_NO_APPS,				/* No traceable application */
	LTTCOMM_NO_SESS,				/* No sessions available */
	LTTCOMM_NO_TRACE,				/* No trace exist */
	LTTCOMM_FATAL,					/* Session daemon had a fatal error */
	LTTCOMM_NO_TRACEABLE,			/* Error for non traceable app */
	LTTCOMM_SELECT_SESS,			/* Must select a session */
	LTTCOMM_EXIST_SESS,				/* Session name already exist */
	LTTCOMM_NO_EVENT,				/* No event found */
	LTTCOMM_KERN_NA,				/* Kernel tracer unavalable */
	LTTCOMM_KERN_SESS_FAIL,			/* Kernel create session failed */
	LTTCOMM_KERN_CHAN_FAIL,			/* Kernel create channel failed */
	KCONSUMERD_COMMAND_SOCK_READY,	/* when kconsumerd command socket ready */
	KCONSUMERD_SUCCESS_RECV_FD,		/* success on receiving fds */
	KCONSUMERD_ERROR_RECV_FD,		/* error on receiving fds */
	KCONSUMERD_POLL_ERROR,			/* Error in polling thread in kconsumerd */
	KCONSUMERD_POLL_NVAL,			/* Poll on closed fd */
	KCONSUMERD_POLL_HUP,			/* All fds have hungup */
	KCONSUMERD_EXIT_SUCCESS,		/* kconsumerd exiting normally */
	KCONSUMERD_EXIT_FAILURE,		/* kconsumerd exiting on error */
	KCONSUMERD_OUTFD_ERROR,			/* error opening the tracefile */
	/* MUST be last element */
	LTTCOMM_NR,						/* Last element */
};

/* commands for kconsumerd */
enum lttcomm_consumerd_command {
	LTTCOMM_ADD_STREAM = 1100,
	LTTCOMM_UPDATE_STREAM, /* pause, delete, start depending on fd state */
	LTTCOMM_STOP, /* delete all */
};

/* state of each fd in consumerd */
enum lttcomm_kconsumerd_fd_state {
	ACTIVE_FD,
	PAUSE_FD,
	DELETE_FD,
};

/*
 * Data structure received from lttng client to session daemon.
 */
struct lttcomm_session_msg {
	u32 cmd_type;    /* enum lttcomm_sessiond_command */
	uuid_t session_uuid;
	char trace_name[NAME_MAX];
	char session_name[NAME_MAX];
	u32 pid;    /* pid_t */
	union {
		struct {
			int auto_session;
		} create_session;
		/* Marker data */
		struct {
			char event_name[NAME_MAX];
		} event;
	} u;
};

/*
 * Data structure for the response from sessiond to the lttng client.
 */
struct lttcomm_lttng_msg {
	u32 cmd_type;   /* enum lttcomm_sessiond_command */
	u32 ret_code;   /* enum lttcomm_return_code */
	u32 pid;        /* pid_t */
	u32 trace_name_offset;
	u32 data_size;
	uuid_t session_uuid;
	/* Contains: trace_name + data */
	char payload[];
};

/*
 * Data structures for the kconsumerd communications
 *
 * The header structure is sent to the kconsumerd daemon to inform
 * how many lttcomm_kconsumerd_msg it is about to receive
 */
struct lttcomm_kconsumerd_header {
	u32 payload_size;
	u32 cmd_type;	/* enum lttcomm_consumerd_command */
	u32 ret_code;	/* enum lttcomm_return_code */
};

/* lttcomm_kconsumerd_msg represents a file descriptor to consume the
 * data and a path name to write it
 */
struct lttcomm_kconsumerd_msg {
	char path_name[PATH_MAX];
	int fd;
	u32 state;    /* enum lttcomm_kconsumerd_fd_state */
	unsigned long max_sb_size; /* the subbuffer size for this channel */
};

extern int lttcomm_create_unix_sock(const char *pathname);
extern int lttcomm_connect_unix_sock(const char *pathname);
extern int lttcomm_accept_unix_sock(int sock);
extern int lttcomm_listen_unix_sock(int sock);
extern int lttcomm_close_unix_sock(int sock);
extern ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t lttcomm_send_unix_sock(int sock, void *buf, size_t len);
extern const char *lttcomm_get_readable_code(enum lttcomm_return_code code);

#endif	/* _LIBLTTSESSIONDCOMM_H */
