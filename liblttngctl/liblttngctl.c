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
static struct lttcomm_lttng_msg llm;
static struct lttcomm_session_msg lsm;

/* Prototypes */
static int check_tracing_group(const char *grp_name);
static int ask_sessiond(void);
static int recvfrom_sessiond(void);
static int set_session_daemon_path(void);
static void reset_data_struct(void);

int lttng_connect_sessiond(void);
int lttng_create_session(const char *name, char *session_id);
int lttng_check_session_daemon(void);

/* Variables */
static char *tracing_group;
static int connected;

/*
 *  ask_sessiond
 *
 *  Send lttcomm_session_msg to the session daemon.
 *
 *  On success, return 0
 *  On error, return error code
 */
static int ask_sessiond(void)
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
 *  recvfrom_sessiond
 *
 *  Receive data from the sessiond socket.
 *
 *  On success, return 0
 *  On error, return recv() error code
 */
static int recvfrom_sessiond(void)
{
	int ret;

	if (!connected) {
		ret = -ENOTCONN;
		goto end;
	}

	ret = lttcomm_recv_unix_sock(sessiond_socket, &llm, sizeof(llm));
	if (ret < 0) {
		goto end;
	}

	/* Check return code */
	if (llm.ret_code != LTTCOMM_OK) {
		ret = -llm.ret_code;
		goto end;
	}

end:
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
 *  lttng_create_session
 *
 *  Create a tracing session using "name" to the session daemon.
 *  If no name is given, the auto session creation is set and
 *  the daemon will take care of finding a name.
 *
 *  On success, return 0 and session_id point to the uuid str.
 *  On error, negative value is returned.
 */
int lttng_create_session(const char *name, char *session_id)
{
	int ret;

	lsm.cmd_type = LTTNG_CREATE_SESSION;
	if (name == NULL) {
		lsm.u.create_session.auto_session = 1;
	} else {
		strncpy(lsm.session_name, name, strlen(name));
		lsm.u.create_session.auto_session = 0;
	}

	/* Ask the session daemon */
	ret = ask_sessiond();
	if (ret < 0) {
		goto end;
	}

	/* Unparse session ID */
	uuid_unparse(llm.session_id, session_id);

end:
	reset_data_struct();

	return ret;
}

/*
 *  lttng_ust_list_apps
 *
 *  Ask the session daemon for all UST traceable
 *  applications.
 *
 *  Return the size of pids.
 */
size_t lttng_ust_list_apps(pid_t **pids)
{
	int ret, first = 0;
	size_t size = 0;
	pid_t *p = NULL;

	lsm.cmd_type = UST_LIST_APPS;

	ret = ask_sessiond();
	if (ret < 0) {
		goto error;
	}

	do {
		ret = recvfrom_sessiond();
		if (ret < 0) {
			goto error;
		}

		if (first == 0) {
			first = 1;
			size = llm.num_pckt;
			p = malloc(sizeof(pid_t) * size);
		}
		p[size - llm.num_pckt] = llm.u.list_apps.pid;
	} while ((llm.num_pckt-1) != 0);

	*pids = p;

	return size;

error:
	return ret;
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
 *  reset_data_struct
 *
 *  Reset session daemon structures.
 */
static void reset_data_struct(void)
{
	memset(&lsm, 0, sizeof(lsm));
	memset(&llm, 0, sizeof(llm));
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
