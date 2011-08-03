/*
 * liblttngctl.c
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
 *  Check if the specified group name exist.
 *
 *  If yes return 0, else return -1.
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
 *  Set sessiond socket path by putting it in the global sessiond_sock_path
 *  variable.
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
 *  Connect to the LTTng session daemon.
 *
 *  On success, return 0. On error, return -1.
 */
static int connect_sessiond(void)
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
 *  Clean disconnect the session daemon.
 */
static int disconnect_sessiond(void)
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
 * Reset the session message structure.
 */
static void reset_session_msg(void)
{
	memset(&lsm, 0, sizeof(struct lttcomm_session_msg));
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

	ret = connect_sessiond();
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
		ret = 0;
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
	disconnect_sessiond();
	reset_session_msg();
	return ret;
}

/*
 * Copy domain to lttcomm_session_msg domain.
 *
 * Return -1 if the domain is unkown.
 */
static int copy_lttng_domain(struct lttng_domain *dom)
{
	switch (dom->type) {
	case LTTNG_DOMAIN_KERNEL:
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_UST_EXEC_NAME:
	case LTTNG_DOMAIN_UST_PID:
	case LTTNG_DOMAIN_UST_PID_FOLLOW_CHILDREN:
		memcpy(&lsm.domain, dom, sizeof(struct lttng_domain));
		return 0;
	default:
		return -1;
	}
}

/*
 *  Start tracing for all trace of the session.
 */
int lttng_start_tracing(const char *session_name)
{
	strncpy(lsm.session_name, session_name, NAME_MAX);
	return ask_sessiond(LTTNG_START_TRACE, NULL);
}

/*
 *  Stop tracing for all trace of the session.
 */
int lttng_stop_tracing(const char *session_name)
{
	strncpy(lsm.session_name, session_name, NAME_MAX);
	return ask_sessiond(LTTNG_STOP_TRACE, NULL);
}

/*
 *  lttng_add_context
 */
int lttng_add_context(struct lttng_domain *domain,
		struct lttng_event_context *ctx, const char *event_name,
		const char *channel_name)
{
	int ret;

	if (channel_name != NULL) {
		strncpy(lsm.u.context.channel_name, channel_name, NAME_MAX);
	}

	if (event_name != NULL) {
		strncpy(lsm.u.context.event_name, event_name, NAME_MAX);
	}

	memcpy(&lsm.u.context.ctx, ctx, sizeof(struct lttng_event_context));

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
		ret = ask_sessiond(LTTNG_KERNEL_ADD_CONTEXT, NULL);
		break;
	case LTTNG_DOMAIN_UST:
		ret = LTTCOMM_NOT_IMPLEMENTED;
		break;
	default:
		ret = LTTCOMM_UNKNOWN_DOMAIN;
		break;
	};

	return ret;
}

/*
 *  lttng_enable_event
 */
int lttng_enable_event(struct lttng_domain *domain,
		struct lttng_event *ev, const char *channel_name)
{
	int ret;

	if (channel_name == NULL) {
		strncpy(lsm.u.enable.channel_name, DEFAULT_CHANNEL_NAME, NAME_MAX);
	} else {
		strncpy(lsm.u.enable.channel_name, channel_name, NAME_MAX);
	}

	switch (domain->type) {
		case LTTNG_DOMAIN_KERNEL:
			if (ev == NULL) {
				ret = ask_sessiond(LTTNG_KERNEL_ENABLE_ALL_EVENT, NULL);
			} else {
				memcpy(&lsm.u.enable.event, ev, sizeof(struct lttng_event));
				ret = ask_sessiond(LTTNG_KERNEL_ENABLE_EVENT, NULL);
			}
			break;
		case LTTNG_DOMAIN_UST:
			ret = LTTCOMM_NOT_IMPLEMENTED;
			break;
		default:
			ret = LTTCOMM_UNKNOWN_DOMAIN;
			break;
	};

	return ret;
}

/*
 * Disable an event in the kernel tracer.
 */
int lttng_disable_event(struct lttng_domain *domain, const char *name,
		const char *channel_name)
{
	int ret;

	if (channel_name == NULL) {
		strncpy(lsm.u.disable.channel_name, DEFAULT_CHANNEL_NAME, NAME_MAX);
	} else {
		strncpy(lsm.u.disable.channel_name, channel_name, NAME_MAX);
	}

	switch (domain->type) {
		case LTTNG_DOMAIN_KERNEL:
			if (name == NULL) {
				ret = ask_sessiond(LTTNG_KERNEL_DISABLE_ALL_EVENT, NULL);
			} else {
				strncpy(lsm.u.disable.name, name, NAME_MAX);
				ret = ask_sessiond(LTTNG_KERNEL_DISABLE_EVENT, NULL);
			}
			break;
		case LTTNG_DOMAIN_UST:
			ret = LTTCOMM_NOT_IMPLEMENTED;
			break;
		default:
			ret = LTTCOMM_UNKNOWN_DOMAIN;
			break;
	};

	return ret;
}

/*
 * Enable recording for a channel for the kernel tracer.
 */
int lttng_enable_channel(struct lttng_domain *domain,
		struct lttng_channel *chan)
{
	int ret;

	memcpy(&lsm.u.channel.chan, chan, sizeof(struct lttng_channel));

	switch (domain->type) {
		case LTTNG_DOMAIN_KERNEL:
			ret = ask_sessiond(LTTNG_KERNEL_ENABLE_CHANNEL, NULL);
			break;
		case LTTNG_DOMAIN_UST:
			ret = LTTCOMM_NOT_IMPLEMENTED;
			break;
		default:
			ret = LTTCOMM_UNKNOWN_DOMAIN;
			break;
	};

	return ret;
}

/*
 * Disable recording for the channel for the kernel tracer.
 */
int lttng_disable_channel(struct lttng_domain *domain, const char *name)
{
	int ret;

	strncpy(lsm.u.disable.channel_name, name, NAME_MAX);

	switch (domain->type) {
		case LTTNG_DOMAIN_KERNEL:
			ret = ask_sessiond(LTTNG_KERNEL_DISABLE_CHANNEL, NULL);
			break;
		case LTTNG_DOMAIN_UST:
			ret = LTTCOMM_NOT_IMPLEMENTED;
			break;
		default:
			ret = LTTCOMM_UNKNOWN_DOMAIN;
			break;
	};

	return ret;
}

/*
 * List all available kernel events.
 *
 * Return the size (bytes) of the list and set the event_list array.
 * On error, return negative value.
 */
int lttng_list_kernel_events(struct lttng_event **events)
{
	int ret;

	ret = ask_sessiond(LTTNG_KERNEL_LIST_EVENTS, (void **) events);

	return ret / sizeof(struct lttng_event);
}

/*
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
 *  Create a brand new session using name.
 */
int lttng_create_session(const char *name, const char *path)
{
	strncpy(lsm.session_name, name, NAME_MAX);
	strncpy(lsm.path, path, PATH_MAX);
	return ask_sessiond(LTTNG_CREATE_SESSION, NULL);
}

/*
 *  Destroy session using name.
 */
int lttng_destroy_session(const char *name)
{
	strncpy(lsm.session_name, name, NAME_MAX);
	return ask_sessiond(LTTNG_DESTROY_SESSION, NULL);
}

/*
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
 * List domain of a session.
 */
int lttng_list_domains(const char *session_name, struct lttng_domain **domains)
{
	int ret;

	strncpy(lsm.session_name, session_name, NAME_MAX);
	ret = ask_sessiond(LTTNG_LIST_DOMAINS, (void**) domains);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_domain);
}

/*
 * List channels of a session
 */
int lttng_list_channels(struct lttng_domain *domain,
		const char *session_name, struct lttng_channel **channels)
{
	int ret;

	strncpy(lsm.session_name, session_name, NAME_MAX);
	ret = copy_lttng_domain(domain);
	if (ret < 0) {
		return -LTTCOMM_UNKNOWN_DOMAIN;
	}

	ret = ask_sessiond(LTTNG_LIST_CHANNELS, (void**) channels);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_channel);
}

/*
 * List events of a session channel.
 */
int lttng_list_events(struct lttng_domain *domain,
		const char *session_name, const char *channel_name,
		struct lttng_event **events)
{
	int ret;

	strncpy(lsm.session_name, session_name, NAME_MAX);
	strncpy(lsm.u.list.channel_name, channel_name, NAME_MAX);
	ret = copy_lttng_domain(domain);
	if (ret < 0) {
		return -LTTCOMM_UNKNOWN_DOMAIN;
	}

	ret = ask_sessiond(LTTNG_LIST_EVENTS, (void**) events);
	if (ret < 0) {
		return ret;
	}

	return ret / sizeof(struct lttng_event);
}

/*
 * Set session name for the current lsm.
 */
void lttng_set_session_name(const char *name)
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
