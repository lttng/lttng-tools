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

#include <lttng/lttng.h>

#include "liblttsessiondcomm.h"
#include "lttngerr.h"
#include "lttng-share.h"

/* Socket to session daemon for communication */
static int sessiond_socket;
static char sessiond_sock_path[PATH_MAX];

/* Communication structure to ltt-sessiond */
static struct lttcomm_session_msg lsm;
static struct lttcomm_lttng_msg llm;

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

end:
	return ret;
}

/*
 *  ask_sessiond
 *
 *  Ask the session daemon a specific command and put the data into buf.
 *
 *  Return size of data (only payload, not header).
 */
static int ask_sessiond(enum lttcomm_sessiond_command lct, void **buf)
{
	int ret;
	size_t size;
	void *data = NULL;

	ret = lttng_connect_sessiond();
	if (ret < 0) {
		goto end;
	}

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

	size = llm.data_size;
	if (size == 0) {
		goto end;
	}

	data = (void*) malloc(size);

	/* Get payload data */
	ret = recv_data_sessiond(data, size);
	if (ret < 0) {
		free(data);
		goto end;
	}

	*buf = data;
	ret = size;

end:
	lttng_disconnect_sessiond();
	return ret;
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
	if (ret < 0 && getuid() != 0) {
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
 *  lttng_start_tracing
 *
 *  Start tracing for all trace of the session.
 */
int lttng_start_tracing(char *session_name)
{
	strncpy(lsm.session_name, session_name, NAME_MAX);
	return ask_sessiond(LTTNG_START_TRACE, NULL);
}

/*
 *  lttng_stop_tracing
 *
 *  Stop tracing for all trace of the session.
 */
int lttng_stop_tracing(char *session_name)
{
	strncpy(lsm.session_name, session_name, NAME_MAX);
	return ask_sessiond(LTTNG_STOP_TRACE, NULL);
}

/*
 * BEGIN Kernel control API
 */

/*
 *  lttng_kernel_add_context
 */
int lttng_kernel_add_context(struct lttng_kernel_context *ctx,
		char *event_name, char *channel_name)
{
	if (channel_name != NULL) {
		strncpy(lsm.u.context.channel_name, channel_name, NAME_MAX);
	}

	if (event_name != NULL) {
		strncpy(lsm.u.context.event_name, event_name, NAME_MAX);
	}

	memcpy(&lsm.u.context.ctx, ctx, sizeof(struct lttng_kernel_context));
	return ask_sessiond(LTTNG_KERNEL_ADD_CONTEXT, NULL);
}

/*
 *  lttng_kernel_enable_event
 */
int lttng_kernel_enable_event(struct lttng_event *ev, char *channel_name)
{
	int ret;

	if (channel_name == NULL) {
		strncpy(lsm.u.enable.channel_name, DEFAULT_CHANNEL_NAME, NAME_MAX);
	} else {
		strncpy(lsm.u.enable.channel_name, channel_name, NAME_MAX);
	}

	if (ev == NULL) {
		ret = ask_sessiond(LTTNG_KERNEL_ENABLE_ALL_EVENT, NULL);
	} else {
		memcpy(&lsm.u.enable.event, ev, sizeof(struct lttng_event));
		ret = ask_sessiond(LTTNG_KERNEL_ENABLE_EVENT, NULL);
	}

	return ret;
}

/*
 *  lttng_kernel_disable_event
 *
 *  Disable an event in the kernel tracer.
 */
int lttng_kernel_disable_event(char *name, char *channel_name)
{
	int ret;

	if (channel_name == NULL) {
		strncpy(lsm.u.disable.channel_name, DEFAULT_CHANNEL_NAME, NAME_MAX);
	} else {
		strncpy(lsm.u.disable.channel_name, channel_name, NAME_MAX);
	}

	if (name == NULL) {
		ret = ask_sessiond(LTTNG_KERNEL_DISABLE_ALL_EVENT, NULL);
	} else {
		strncpy(lsm.u.disable.name, name, NAME_MAX);
		ret = ask_sessiond(LTTNG_KERNEL_DISABLE_EVENT, NULL);
	}

	return ret;
}

/*
 *  lttng_kernel_enable_channel
 *
 *  Enable recording for a channel for the kernel tracer.
 */
int lttng_kernel_enable_channel(char *name)
{
	strncpy(lsm.u.enable.channel_name, name, NAME_MAX);
	return ask_sessiond(LTTNG_KERNEL_ENABLE_CHANNEL, NULL);
}

/*
 *  lttng_kernel_disable_channel
 *
 *  Disable recording for the channel for the kernel tracer.
 */
int lttng_kernel_disable_channel(char *name)
{
	strncpy(lsm.u.disable.channel_name, name, NAME_MAX);
	return ask_sessiond(LTTNG_KERNEL_DISABLE_CHANNEL, NULL);
}

/*
 *  lttng_kernel_create_channel
 *
 *  Create a channel in the kernel tracer.
 */
int lttng_kernel_create_channel(struct lttng_channel *chan)
{
	memcpy(&lsm.u.channel.chan, chan, sizeof(struct lttng_channel));
	return ask_sessiond(LTTNG_KERNEL_CREATE_CHANNEL, NULL);
}

/*
 *  lttng_list_events
 *
 *  List all available events in the kernel.
 *
 *  Return the size (bytes) of the list and set the event_list array.
 *  On error, return negative value.
 */
int lttng_kernel_list_events(char **event_list)
{
	return ask_sessiond(LTTNG_KERNEL_LIST_EVENTS, (void **) event_list);
}

/*
 * END Kernel control API
 */

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
 *  lttng_ust_list_apps
 *
 *  Ask the session daemon for all UST traceable applications.
 *
 *  Return the number of pids.
 *  On error, return negative value.
 */
int lttng_ust_list_traceable_apps(pid_t **pids)
{
	int ret;

	ret = ask_sessiond(LTTNG_LIST_TRACEABLE_APPS, (void**) pids);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(pid_t);
}

/*
 *  lttng_list_traces
 *
 *  Ask the session daemon for all traces (kernel and ust) for the session
 *  identified by name.
 *
 *  Return the number of traces.
 *  On error, return negative value.
 */
/*
int lttng_list_traces(char *session_name, struct lttng_trace **traces)
{
	int ret;

	strncpy(lsm.session_name, session_name, NAME_MAX);

	ret = ask_sessiond(LTTNG_LIST_TRACES, (void **) traces);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_trace);
}
*/

/*
 *  lttng_create_session
 *
 *  Create a brand new session using name.
 */
int lttng_create_session(char *name, char *path)
{
	strncpy(lsm.session_name, name, NAME_MAX);
	strncpy(lsm.path, path, PATH_MAX);
	return ask_sessiond(LTTNG_CREATE_SESSION, NULL);
}

/*
 *  lttng_destroy_session
 *
 *  Destroy session using name.
 */
int lttng_destroy_session(char *name)
{
	strncpy(lsm.session_name, name, NAME_MAX);
	return ask_sessiond(LTTNG_DESTROY_SESSION, NULL);
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

void lttng_set_session_name(char *name)
{
	strncpy(lsm.session_name, name, NAME_MAX);
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
 *  Yes, return 1
 *  No, return 0
 *  Error, return negative value
 */
int lttng_session_daemon_alive(void)
{
	int ret;

	ret = set_session_daemon_path();
	if (ret < 0) {
		/* Error */
		return ret;
	}

	/* If socket exist, we consider the daemon started */
	ret = access(sessiond_sock_path, F_OK);
	if (ret < 0) {
		/* Not alive */
		return 0;
	}

	/* Is alive */
	return 1;
}

/*
 * lib constructor
 */
static void __attribute__((constructor)) init()
{
	/* Set default session group */
	lttng_set_tracing_group(LTTNG_DEFAULT_TRACING_GROUP);
}
