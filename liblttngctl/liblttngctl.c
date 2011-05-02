/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
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
 */

#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lttng/liblttngctl.h>

#include "liblttsessiondcomm.h"
#include "lttngerr.h"

/* Socket to session daemon for communication */
static int sessiond_socket;
static char sessiond_sock_path[PATH_MAX];

/* Communication structure to ltt-sessiond */
static struct lttcomm_session_msg lsm;
static struct lttcomm_lttng_msg llm;

/* Prototypes */
static int check_tracing_group(const char *grp_name);
static int ask_sessiond(enum lttcomm_command_type lct, void **buf);
static int recv_data_sessiond(void *buf, size_t len);
static int send_data_sessiond(void);
static int set_session_daemon_path(void);

/* Variables */
static char *tracing_group;
static int connected;

/*
 *  send_data_sessiond
 *
 *  Send lttcomm_session_msg to the session daemon.
 *
 *  On success, return 0
 *  On error, return error code
 */
static int send_data_sessiond(void)
{
	int ret;

	if (!connected) {
		ret = -ENOTCONN;
		goto end;
	}

	ret = lttcomm_send_unix_sock(sessiond_socket, &lsm, sizeof(lsm));

end:
	return ret;
}

/*
 *  recv_data_sessiond
 *
 *  Receive data from the sessiond socket.
 *
 *  On success, return 0
 *  On error, return recv() error code
 */
static int recv_data_sessiond(void *buf, size_t len)
{
	int ret;

	if (!connected) {
		ret = -ENOTCONN;
		goto end;
	}

	ret = lttcomm_recv_unix_sock(sessiond_socket, buf, len);
	if (ret < 0) {
		goto end;
	}

end:
	return ret;
}

/*
 *  ask_sessiond
 *
 *  Ask the session daemon a specific command
 *  and put the data into buf.
 *
 *  Return size of data (only payload, not header).
 */
static int ask_sessiond(enum lttcomm_command_type lct, void **buf)
{
	int ret;
	size_t size;
	void *data = NULL;

	lsm.cmd_type = lct;

	/* Send command to session daemon */
	ret = send_data_sessiond();
	if (ret < 0) {
		goto end;
	}

	/* Get header from data transmission */
	ret = recv_data_sessiond(&llm, sizeof(llm));
	if (ret < 0) {
		goto end;
	}

	/* Check error code if OK */
	if (llm.ret_code != LTTCOMM_OK) {
		ret = -llm.ret_code;
		goto end;
	}

	size = llm.size_payload;
	if (size == 0) {
		goto end;
	}

	data = (void*) malloc(size);

	/* Get payload data */
	ret = recv_data_sessiond(data, size);
	if (ret < 0) {
		goto end;
	}

	*buf = data;
	ret = size;

end:
	/* Reset lsm data struct */
	memset(&lsm, 0, sizeof(lsm));
	return ret;
}

/*
 *  lttng_get_readable_code
 *
 *  Return a human readable string of code
 */
const char *lttng_get_readable_code(int code)
{
	if (code > -LTTCOMM_OK) {
		return "Ended with errors";
	}

	return lttcomm_get_readable_code(code);
}

/*
 *  lttng_ust_start_trace
 *
 *  Request a trace start for pid.
 */
int lttng_ust_start_trace(pid_t pid)
{
	int ret;

	lsm.pid = pid;
	ret = ask_sessiond(UST_START_TRACE, NULL);

	return ret;
}

/*
 *  lttng_ust_create_trace
 *
 *  Request a trace creation for pid.
 */
int lttng_ust_create_trace(pid_t pid)
{
	int ret;

	lsm.pid = pid;
	ret = ask_sessiond(UST_CREATE_TRACE, NULL);

	return ret;
}

/*
 *  lttng_ust_list_apps
 *
 *  Ask the session daemon for all UST traceable
 *  applications.
 *
 *  Return the number of pids.
 *  On error, return negative value.
 */
int lttng_ust_list_apps(pid_t **pids)
{
	int ret;

	ret = ask_sessiond(UST_LIST_APPS, (void**) pids);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(pid_t);
}

/*
 *  lttng_list_traces
 *
 *  Ask the session daemon for all traces (kernel and ust)
 *  for the session identified by uuid.
 *
 *  Return the number of traces.
 */
int lttng_list_traces(uuid_t *uuid, struct lttng_trace **traces)
{
	int ret;

	uuid_copy(lsm.session_id, *uuid);

	ret = ask_sessiond(LTTNG_LIST_TRACES, (void **) traces);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_trace);
}

/*
 *  lttng_create_session
 *
 *  Create a brand new session using name. Allocate
 *  the session_id param pointing to the UUID.
 */
int lttng_create_session(char *name, uuid_t *session_id)
{
	int ret;

	strncpy(lsm.session_name, name, sizeof(lsm.session_name));
	lsm.session_name[sizeof(lsm.session_name) - 1] = '\0';

	ret = ask_sessiond(LTTNG_CREATE_SESSION, NULL);
	if (ret < 0) {
		goto end;
	}

	uuid_copy(*session_id, llm.session_id);

end:
	return ret;
}

/*
 *  lttng_destroy_session
 *
 *  Destroy session using name.
 */
int lttng_destroy_session(uuid_t *uuid)
{
	int ret;

	uuid_copy(lsm.session_id, *uuid);

	ret = ask_sessiond(LTTNG_DESTROY_SESSION, NULL);
	if (ret < 0) {
		goto end;
	}

end:
	return ret;
}

/*
 *  lttng_list_sessions
 *
 *  Ask the session daemon for all available sessions.
 *
 *  Return number of session.
 *  On error, return negative value.
 */
int lttng_list_sessions(struct lttng_session **sessions)
{
	int ret;

	ret = ask_sessiond(LTTNG_LIST_SESSIONS, (void**) sessions);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_session);
}

/*
 *  lttng_connect_sessiond
 *
 *  Connect to the LTTng session daemon.
 *  On success, return 0
 *  On error, return a negative value
 */
int lttng_connect_sessiond(void)
{
	int ret;

	ret = set_session_daemon_path();
	if (ret < 0) {
		return ret;
	}

	/* Connect to the sesssion daemon */
	ret = lttcomm_connect_unix_sock(sessiond_sock_path);
	if (ret < 0) {
		return ret;
	}

	sessiond_socket = ret;
	connected = 1;

	return 0;
}

/*
 *  lttng_disconnect_sessiond
 *
 *  Clean disconnect the session daemon.
 */
int lttng_disconnect_sessiond(void)
{
	int ret = 0;

	if (connected) {
		ret = lttcomm_close_unix_sock(sessiond_socket);
		sessiond_socket = 0;
		connected = 0;
	}

	return ret;
}

/*
 *  lttng_set_current_session_uuid
 *
 *  Set the session uuid for current lsm.
 */
void lttng_set_current_session_uuid(char *uuid)
{
	uuid_parse(uuid, lsm.session_id);
}

/*
 *  lttng_set_tracing_group
 *
 *  Set tracing group variable with name. This function
 *  allocate memory pointed by tracing_group.
 */
int lttng_set_tracing_group(const char *name)
{
	if (asprintf(&tracing_group, "%s", name) < 0) {
		return -ENOMEM;
	}

	return 0;
}

/*
 *  lttng_check_session_daemon
 *
 *  Return 0 if a sesssion daemon is available
 *  else return -1
 */
int lttng_check_session_daemon(void)
{
	int ret;

	ret = set_session_daemon_path();
	if (ret < 0) {
		return ret;
	}

	/* If socket exist, we consider the daemon started */
	ret = access(sessiond_sock_path, F_OK);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

/*
 *  set_session_daemon_path
 *
 *  Set sessiond socket path by putting it in 
 *  the global sessiond_sock_path variable.
 */
static int set_session_daemon_path(void)
{
	int ret;

	/* Are we in the tracing group ? */
	ret = check_tracing_group(tracing_group);
	if (ret < 0) {
		if (sprintf(sessiond_sock_path, DEFAULT_HOME_CLIENT_UNIX_SOCK,
					getenv("HOME")) < 0) {
			return -ENOMEM;
		}
	} else {
		strncpy(sessiond_sock_path, DEFAULT_GLOBAL_CLIENT_UNIX_SOCK,
				sizeof(DEFAULT_GLOBAL_CLIENT_UNIX_SOCK));
	}

	return 0;
}

/*
 *  check_tracing_group
 *
 *  Check if the specified group name exist.
 *  If yes, 0, else -1
 */
static int check_tracing_group(const char *grp_name)
{
	struct group *grp_tracing;	/* no free(). See getgrnam(3) */
	gid_t *grp_list;
	int grp_list_size, grp_id, i;
	int ret = -1;

	/* Get GID of group 'tracing' */
	grp_tracing = getgrnam(grp_name);
	if (grp_tracing == NULL) {
		/* NULL means not found also. getgrnam(3) */
		if (errno != 0) {
			perror("getgrnam");
		}
		goto end;
	}

	/* Get number of supplementary group IDs */
	grp_list_size = getgroups(0, NULL);
	if (grp_list_size < 0) {
		perror("getgroups");
		goto end;
	}

	/* Alloc group list of the right size */
	grp_list = malloc(grp_list_size * sizeof(gid_t));
	grp_id = getgroups(grp_list_size, grp_list);
	if (grp_id < -1) {
		perror("getgroups");
		goto free_list;
	}

	for (i = 0; i < grp_list_size; i++) {
		if (grp_list[i] == grp_tracing->gr_gid) {
			ret = 0;
			break;
		}
	}

free_list:
	free(grp_list);

end:
	return ret;
}

/*
 * lib constructor
 */
static void __attribute__((constructor)) init()
{
	/* Set default session group */
	lttng_set_tracing_group(DEFAULT_TRACING_GROUP);
}
