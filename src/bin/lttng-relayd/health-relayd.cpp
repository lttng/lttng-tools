/*
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <urcu/list.h>
#include <poll.h>
#include <unistd.h>
#include <sys/mman.h>
#include <urcu/compiler.h>
#include <inttypes.h>

#include <common/defaults.h>
#include <common/common.h>
#include <common/consumer/consumer.h>
#include <common/consumer/consumer-timer.h>
#include <common/compat/poll.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/utils.h>
#include <common/compat/getenv.h>
#include <common/fd-tracker/utils.h>

#include "lttng-relayd.h"
#include "health-relayd.h"

/* Global health check unix path */
static
char health_unix_sock_path[PATH_MAX];

int health_quit_pipe[2] = { -1, -1 };

/*
 * Check if the thread quit pipe was triggered.
 *
 * Return 1 if it was triggered else 0;
 */
static
int check_health_quit_pipe(int fd, uint32_t events)
{
	if (fd == health_quit_pipe[0] && (events & LPOLLIN)) {
		return 1;
	}

	return 0;
}

/*
 * Send data on a unix socket using the liblttsessiondcomm API.
 *
 * Return lttcomm error code.
 */
static int send_unix_sock(int sock, void *buf, size_t len)
{
	/* Check valid length */
	if (len == 0) {
		return -1;
	}

	return lttcomm_send_unix_sock(sock, buf, len);
}

static int create_lttng_rundir_with_perm(const char *rundir)
{
	int ret;

	DBG3("Creating LTTng run directory: %s", rundir);

	ret = mkdir(rundir, S_IRWXU);
	if (ret < 0) {
		if (errno != EEXIST) {
			ERR("Unable to create %s", rundir);
			goto error;
		} else {
			ret = 0;
		}
	} else if (ret == 0) {
		int is_root = !getuid();

		if (is_root) {
			gid_t gid;

			ret = utils_get_group_id(tracing_group_name, true, &gid);
			if (ret) {
				/* Default to root group. */
				gid = 0;
			}

			ret = chown(rundir, 0, gid);
			if (ret < 0) {
				ERR("Unable to set group on %s", rundir);
				PERROR("chown");
				ret = -1;
				goto error;
			}

			ret = chmod(rundir,
					S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
			if (ret < 0) {
				ERR("Unable to set permissions on %s", health_unix_sock_path);
				PERROR("chmod");
				ret = -1;
				goto error;
			}
		}
	}

error:
	return ret;
}

static
int parse_health_env(void)
{
	const char *health_path;

	health_path = lttng_secure_getenv(LTTNG_RELAYD_HEALTH_ENV);
	if (health_path) {
		strncpy(health_unix_sock_path, health_path,
			PATH_MAX);
		health_unix_sock_path[PATH_MAX - 1] = '\0';
	}

	return 0;
}

static
int setup_health_path(void)
{
	int is_root, ret = 0;
	const char *home_path = NULL;
	char *rundir = NULL, *relayd_path = NULL;

	ret = parse_health_env();
	if (ret) {
		return ret;
	}

	is_root = !getuid();

	if (is_root) {
		rundir = strdup(DEFAULT_LTTNG_RUNDIR);
		if (!rundir) {
			ret = -ENOMEM;
			goto end;
		}
	} else {
		/*
		 * Create rundir from home path. This will create something like
		 * $HOME/.lttng
		 */
		home_path = utils_get_home_dir();

		if (home_path == NULL) {
			/* TODO: Add --socket PATH option */
			ERR("Can't get HOME directory for sockets creation.");
			ret = -EPERM;
			goto end;
		}

		ret = asprintf(&rundir, DEFAULT_LTTNG_HOME_RUNDIR, home_path);
		if (ret < 0) {
			ret = -ENOMEM;
			goto end;
		}
	}

	ret = asprintf(&relayd_path, DEFAULT_RELAYD_PATH, rundir);
	if (ret < 0) {
		ret = -ENOMEM;
		goto end;
	}

	ret = create_lttng_rundir_with_perm(rundir);
	if (ret < 0) {
		goto end;
	}

	ret = create_lttng_rundir_with_perm(relayd_path);
	if (ret < 0) {
		goto end;
	}

	if (is_root) {
		if (strlen(health_unix_sock_path) != 0) {
			goto end;
		}
		snprintf(health_unix_sock_path, sizeof(health_unix_sock_path),
			DEFAULT_GLOBAL_RELAY_HEALTH_UNIX_SOCK,
			(int) getpid());
	} else {
		/* Set health check Unix path */
		if (strlen(health_unix_sock_path) != 0) {
			goto end;
		}

		snprintf(health_unix_sock_path, sizeof(health_unix_sock_path),
			DEFAULT_HOME_RELAY_HEALTH_UNIX_SOCK,
			home_path, (int) getpid());
	}

end:
	free(rundir);
	free(relayd_path);
	return ret;
}

static
int accept_unix_socket(void *data, int *out_fd)
{
	int ret;
	int accepting_sock = *((int *) data);

	ret = lttcomm_accept_unix_sock(accepting_sock);
	if (ret < 0) {
		goto end;
	}

	*out_fd = ret;
	ret = 0;
end:
	return ret;
}

static
int open_unix_socket(void *data, int *out_fd)
{
	int ret;
	const char *path = (const char *) data;

	ret = lttcomm_create_unix_sock(path);
	if (ret < 0) {
		goto end;
	}

	*out_fd = ret;
	ret = 0;
end:
	return ret;
}

/*
 * Thread managing health check socket.
 */
void *thread_manage_health(void *data)
{
	int sock = -1, new_sock = -1, ret, i, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct health_comm_msg msg;
	struct health_comm_reply reply;
	int is_root;
	char *sock_name;

	DBG("[thread] Manage health check started");

	setup_health_path();

	rcu_register_thread();

	/* We might hit an error path before this is created. */
	lttng_poll_init(&events);

	/* Create unix socket */
	ret = asprintf(&sock_name, "Unix socket @ %s", health_unix_sock_path);
	if (ret == -1) {
		PERROR("Failed to allocate unix socket name");
		err = -1;
		goto error;
	}
	ret = fd_tracker_open_unsuspendable_fd(the_fd_tracker, &sock,
			(const char **) &sock_name, 1, open_unix_socket,
			health_unix_sock_path);
	free(sock_name);
	if (ret < 0) {
		ERR("Unable to create health check Unix socket");
		err = -1;
		goto error;
	}

	is_root = !getuid();
	if (is_root) {
		/* lttng health client socket path permissions */
		gid_t gid;

		ret = utils_get_group_id(tracing_group_name, true, &gid);
		if (ret) {
			/* Default to root group. */
			gid = 0;
		}

		ret = chown(health_unix_sock_path, 0, gid);
		if (ret < 0) {
			ERR("Unable to set group on %s", health_unix_sock_path);
			PERROR("chown");
			err = -1;
			goto error;
		}

		ret = chmod(health_unix_sock_path,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (ret < 0) {
			ERR("Unable to set permissions on %s", health_unix_sock_path);
			PERROR("chmod");
			err = -1;
			goto error;
		}
	}

	/*
	 * Set the CLOEXEC flag. Return code is useless because either way, the
	 * show must go on.
	 */
	(void) utils_set_fd_cloexec(sock);

	ret = lttcomm_listen_unix_sock(sock);
	if (ret < 0) {
		goto error;
	}

	/* Size is set to 2 for the unix socket and quit pipe. */
	ret = fd_tracker_util_poll_create(the_fd_tracker,
			"Health management thread epoll", &events, 2,
			LTTNG_CLOEXEC);
	if (ret < 0) {
		ERR("Poll set creation failed");
		goto error;
	}

	ret = lttng_poll_add(&events, health_quit_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLPRI);
	if (ret < 0) {
		goto error;
	}

	lttng_relay_notify_ready();

	while (1) {
		char *accepted_socket_name;

		DBG("Health check ready");

		/* Inifinite blocking call, waiting for transmission */
restart:
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				goto restart;
			}
			goto error;
		}

		nb_fd = ret;

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_health_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Event on the registration socket */
			if (pollfd == sock) {
				if (revents & LPOLLIN) {
					continue;
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Health socket poll error");
					goto error;
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			}
		}

		ret = asprintf(&accepted_socket_name, "Socket accepted from unix socket @ %s",
				health_unix_sock_path);
		if (ret == -1) {
			PERROR("Failed to allocate name of accepted socket from unix socket @ %s",
					health_unix_sock_path);
			goto error;
		}
		ret = fd_tracker_open_unsuspendable_fd(the_fd_tracker, &new_sock,
				(const char **) &accepted_socket_name, 1,
				accept_unix_socket, &sock);
		free(accepted_socket_name);
		if (ret < 0) {
			goto error;
		}

		/*
		 * Set the CLOEXEC flag. Return code is useless because either way, the
		 * show must go on.
		 */
		(void) utils_set_fd_cloexec(new_sock);

		DBG("Receiving data from client for health...");
		ret = lttcomm_recv_unix_sock(new_sock, (void *)&msg, sizeof(msg));
		if (ret <= 0) {
			DBG("Nothing recv() from client... continuing");
			ret = fd_tracker_close_unsuspendable_fd(the_fd_tracker,
					&new_sock, 1, fd_tracker_util_close_fd,
					NULL);
			if (ret) {
				PERROR("close");
			}
			new_sock = -1;
			continue;
		}

		rcu_thread_online();

		LTTNG_ASSERT(msg.cmd == HEALTH_CMD_CHECK);

		memset(&reply, 0, sizeof(reply));
		for (i = 0; i < NR_HEALTH_RELAYD_TYPES; i++) {
			/*
			 * health_check_state return 0 if thread is in
			 * error.
			 */
			if (!health_check_state(health_relayd, i)) {
				reply.ret_code |= 1ULL << i;
			}
		}

		DBG2("Health check return value %" PRIx64, reply.ret_code);

		ret = send_unix_sock(new_sock, (void *) &reply, sizeof(reply));
		if (ret < 0) {
			ERR("Failed to send health data back to client");
		}

		/* End of transmission */
		ret = fd_tracker_close_unsuspendable_fd(the_fd_tracker,
				&new_sock, 1, fd_tracker_util_close_fd,
				NULL);
		if (ret) {
			PERROR("close");
		}
		new_sock = -1;
	}

error:
	lttng_relay_stop_threads();
exit:
	if (err) {
		ERR("Health error occurred in %s", __func__);
	}
	DBG("Health check thread dying");
	unlink(health_unix_sock_path);
	if (sock >= 0) {
		ret = fd_tracker_close_unsuspendable_fd(the_fd_tracker, &sock,
				1, fd_tracker_util_close_fd, NULL);
		if (ret) {
			PERROR("close");
		}
	}

	/*
	 * We do NOT rmdir rundir nor the relayd path because there are
	 * other processes using them.
	 */

	(void) fd_tracker_util_poll_clean(the_fd_tracker, &events);

	rcu_unregister_thread();
	return NULL;
}