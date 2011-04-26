/* Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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

/* Default unix socket path */
#define DEFAULT_GLOBAL_CLIENT_UNIX_SOCK		"/tmp/client-ltt-sessiond"
#define DEFAULT_GLOBAL_APPS_UNIX_SOCK		"/tmp/apps-ltt-sessiond"
#define DEFAULT_HOME_APPS_UNIX_SOCK			"%s/.apps-ltt-sessiond"
#define DEFAULT_HOME_CLIENT_UNIX_SOCK		"%s/.client-ltt-sessiond"

/* Queue size of listen(2) */
#define MAX_LISTEN 10

/* Get the error code index from 0 since
 * LTTCOMM_OK start at 1000
 */
#define LTTCOMM_ERR_INDEX(code) (code - LTTCOMM_OK)

enum lttcomm_command_type {
	LTTNG_CREATE_SESSION,
	LTTNG_DESTROY_SESSION,
	LTTNG_FORCE_SUBBUF_SWITCH,
	LTTNG_GET_ALL_SESSION,
	LTTNG_GET_SOCK_PATH,
	LTTNG_GET_SUBBUF_NUM_SIZE,
	LTTNG_LIST_MARKERS,
	LTTNG_LIST_SESSIONS,
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
	LTTCOMM_OK = 1000,		/* Ok */
	LTTCOMM_ERR,			/* Unknown Error */
	LTTCOMM_UND,			/* Undefine command */
	LTTCOMM_ALLOC_FAIL,		/* Trace allocation fail */
	LTTCOMM_NO_SESSION,		/* No session found */
	LTTCOMM_CREATE_FAIL,	/* Create trace fail */
	LTTCOMM_SESSION_FAIL,	/* Create session fail */
	LTTCOMM_START_FAIL,		/* Start tracing fail */
	LTTCOMM_LIST_FAIL,		/* Listing apps fail */
	LTTCOMM_NO_APPS,		/* No traceable application */
	LTTCOMM_NO_SESS,		/* No sessions available */
	LTTCOMM_FATAL,			/* Session daemon had a fatal error */
	LTTCOMM_NR,				/* Last element */
};

/*
 * Data structure for ltt-session received message
 */
struct lttcomm_session_msg {
	/* Common data to almost all command */
	enum lttcomm_command_type cmd_type;
	char session_id[37];
	char trace_name[NAME_MAX];
	char session_name[NAME_MAX];
	pid_t pid;
	union {
		struct {
			int auto_session;
		} create_session;
		/* Marker data */
		struct {
			char channel[NAME_MAX];
			char marker[NAME_MAX];
		} marker;
		/* SET_SOCK_PATH */
		struct {
			char sock_path[PATH_MAX];
		} sock_path;
		/* SET_SUBBUF_NUM */
		struct {
			unsigned int subbuf_num;
			char channel[NAME_MAX];
		} subbuf_num;
		/* SET_SUBBUF_SIZE */
		struct {
			unsigned int subbuf_size;
			char channel[NAME_MAX];
		} subbuf_size;
	} u;
};

/*
 * Data structure for the lttng client response.
 *
 * This data structure is the control struct use in
 * the header of the transmission. NEVER put variable
 * size data in here.
 */
struct lttcomm_lttng_msg {
	enum lttcomm_command_type cmd_type;
	enum lttcomm_return_code ret_code;
	char session_id[37];
	pid_t pid;
	char trace_name[NAME_MAX];
	unsigned int size_payload;
};

extern int lttcomm_create_unix_sock(const char *pathname);
extern int lttcomm_connect_unix_sock(const char *pathname);
extern int lttcomm_accept_unix_sock(int sock);
extern int lttcomm_listen_unix_sock(int sock);
extern ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t lttcomm_send_unix_sock(int sock, void *buf, size_t len);
extern const char *lttcomm_get_readable_code(enum lttcomm_return_code code);

#endif	/* _LIBLTTSESSIONDCOMM_H */
