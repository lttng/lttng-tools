/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Julien Desfossez <julien.desfossez@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
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

#include <lttng/lttng.h>
#include "lttng-share.h"

/* Default unix socket path */
#define DEFAULT_GLOBAL_CLIENT_UNIX_SOCK		LTTNG_RUNDIR "/client-ltt-sessiond"
#define DEFAULT_GLOBAL_APPS_UNIX_SOCK		LTTNG_RUNDIR "/apps-ltt-sessiond"
#define DEFAULT_HOME_APPS_UNIX_SOCK			"%s/.apps-ltt-sessiond"
#define DEFAULT_HOME_CLIENT_UNIX_SOCK		"%s/.client-ltt-sessiond"

/* Queue size of listen(2) */
#define MAX_LISTEN 10

/* Get the error code index from 0 since
 * LTTCOMM_OK start at 1000
 */
#define LTTCOMM_ERR_INDEX(code) (code - LTTCOMM_OK)

enum lttcomm_sessiond_command {
	/* Tracer context command */
	LTTNG_KERNEL_ADD_CONTEXT,
	LTTNG_KERNEL_DISABLE_CHANNEL,
	LTTNG_KERNEL_DISABLE_EVENT,
	LTTNG_KERNEL_DISABLE_ALL_EVENT,
	LTTNG_KERNEL_ENABLE_CHANNEL,
	LTTNG_KERNEL_ENABLE_EVENT,
	LTTNG_KERNEL_ENABLE_ALL_EVENT,
	LTTNG_KERNEL_LIST_EVENTS,
	/* Session daemon context command */
	LTTNG_CREATE_SESSION,
	LTTNG_DESTROY_SESSION,
	LTTNG_LIST_SESSIONS,
	LTTNG_LIST_TRACES,
	LTTNG_LIST_EVENTS,
	LTTNG_LIST_TRACEABLE_APPS,
	LTTNG_START_TRACE,
	LTTNG_STOP_TRACE,
};

/*
 * lttcomm error code.
 */
enum lttcomm_return_code {
	LTTCOMM_OK = 1000,				/* Ok */
	LTTCOMM_ERR,					/* Unknown Error */
	LTTCOMM_UND,					/* Undefine command */
	LTTCOMM_NOT_IMPLEMENTED,        /* Command not implemented */
	LTTCOMM_UNKNOWN_DOMAIN,         /* Tracing domain not known */
	LTTCOMM_ALLOC_FAIL,				/* Trace allocation fail */
	LTTCOMM_NO_SESSION,				/* No session found */
	LTTCOMM_CREATE_FAIL,			/* Create trace fail */
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
	LTTCOMM_KERN_NA,				/* Kernel tracer unavalable */
	LTTCOMM_KERN_EVENT_EXIST,       /* Kernel event already exists */
	LTTCOMM_KERN_SESS_FAIL,			/* Kernel create session failed */
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
	KCONSUMERD_COMMAND_SOCK_READY,	/* when kconsumerd command socket ready */
	KCONSUMERD_SUCCESS_RECV_FD,		/* success on receiving fds */
	KCONSUMERD_ERROR_RECV_FD,		/* error on receiving fds */
	KCONSUMERD_POLL_ERROR,			/* Error in polling thread in kconsumerd */
	KCONSUMERD_POLL_NVAL,			/* Poll on closed fd */
	KCONSUMERD_POLL_HUP,			/* All fds have hungup */
	KCONSUMERD_EXIT_SUCCESS,		/* kconsumerd exiting normally */
	KCONSUMERD_EXIT_FAILURE,		/* kconsumerd exiting on error */
	KCONSUMERD_OUTFD_ERROR,			/* error opening the tracefile */
	KCONSUMERD_SPLICE_EBADF,		/* EBADF from splice(2) */
	KCONSUMERD_SPLICE_EINVAL,		/* EINVAL from splice(2) */
	KCONSUMERD_SPLICE_ENOMEM,		/* ENOMEM from splice(2) */
	KCONSUMERD_SPLICE_ESPIPE,		/* ESPIPE from splice(2) */
	/* MUST be last element */
	LTTCOMM_NR,						/* Last element */
};

/*
 * Data structure received from lttng client to session daemon.
 */
struct lttcomm_session_msg {
	u32 cmd_type;    /* enum lttcomm_sessiond_command */
	char session_name[NAME_MAX];
	char path[PATH_MAX];
	pid_t pid;
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
	} u;
};

/*
 * Data structure for the response from sessiond to the lttng client.
 */
struct lttcomm_lttng_msg {
	u32 cmd_type;   /* enum lttcomm_sessiond_command */
	u32 ret_code;   /* enum lttcomm_return_code */
	u32 pid;        /* pid_t */
	u32 data_size;
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
	u32 cmd_type;	/* enum kconsumerd_command */
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
extern ssize_t lttcomm_send_fds_unix_sock(int sock, void *buf, int *fds, size_t nb_fd, size_t len);
extern ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t lttcomm_send_unix_sock(int sock, void *buf, size_t len);
extern const char *lttcomm_get_readable_code(enum lttcomm_return_code code);

#endif	/* _LIBLTTSESSIONDCOMM_H */
