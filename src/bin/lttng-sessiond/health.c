/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "lttng-sessiond.h"
#include "health-sessiond.h"
#include <common/macros.h>
#include <common/error.h>
#include <common/utils.h>
#include <common/pipe.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "utils.h"
#include "thread.h"

static void cleanup_health_management_thread(void *thread_data)
{
	struct lttng_pipe *quit_pipe = thread_data;

	lttng_pipe_destroy(quit_pipe);
}

/*
 * Thread managing health check socket.
 */
static void *thread_manage_health(void *thread_data)
{
	const bool is_root = (getuid() == 0);
	int sock = -1, new_sock = -1, ret, i, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct health_comm_msg msg;
	struct health_comm_reply reply;
	/* Thread-specific quit pipe. */
	struct lttng_pipe *quit_pipe = thread_data;
	const int quit_pipe_read_fd = lttng_pipe_get_readfd(quit_pipe);

	DBG("[thread] Manage health check started");

	rcu_register_thread();

	/*
	 * Created with a size of two for:
	 *   - client socket
	 *   - thread quit pipe
	 */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	/* Create unix socket */
	sock = lttcomm_create_unix_sock(config.health_unix_sock_path.value);
	if (sock < 0) {
		ERR("Unable to create health check Unix socket");
		goto error;
	}

	if (is_root) {
		/* lttng health client socket path permissions */
		ret = chown(config.health_unix_sock_path.value, 0,
				utils_get_group_id(config.tracing_group_name.value));
		if (ret < 0) {
			ERR("Unable to set group on %s", config.health_unix_sock_path.value);
			PERROR("chown");
			goto error;
		}

		ret = chmod(config.health_unix_sock_path.value,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (ret < 0) {
			ERR("Unable to set permissions on %s", config.health_unix_sock_path.value);
			PERROR("chmod");
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

	ret = lttng_poll_add(&events, quit_pipe_read_fd, LPOLLIN | LPOLLERR);
	if (ret < 0) {
		goto error;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLPRI);
	if (ret < 0) {
		goto error;
	}

	sessiond_notify_ready();

	while (1) {
		DBG("Health check ready");

		/* Infinite blocking call, waiting for transmission */
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

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
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
			} else {
				/* Event on the thread's quit pipe. */
				err = 0;
				goto exit;
			}
		}

		new_sock = lttcomm_accept_unix_sock(sock);
		if (new_sock < 0) {
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
			ret = close(new_sock);
			if (ret) {
				PERROR("close");
			}
			continue;
		}

		rcu_thread_online();

		memset(&reply, 0, sizeof(reply));
		for (i = 0; i < NR_HEALTH_SESSIOND_TYPES; i++) {
			/*
			 * health_check_state returns 0 if health is
			 * bad.
			 */
			if (!health_check_state(health_sessiond, i)) {
				reply.ret_code |= 1ULL << i;
			}
		}

		DBG2("Health check return value %" PRIx64, reply.ret_code);

		ret = lttcomm_send_unix_sock(new_sock, (void *) &reply,
				sizeof(reply));
		if (ret < 0) {
			ERR("Failed to send health data back to client");
		}

		/* End of transmission */
		ret = close(new_sock);
		if (ret) {
			PERROR("close");
		}
	}

exit:
error:
	if (err) {
		ERR("Health error occurred in %s", __func__);
	}
	DBG("Health check thread dying");
	unlink(config.health_unix_sock_path.value);
	if (sock >= 0) {
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
	}

	lttng_poll_clean(&events);
	rcu_unregister_thread();
	return NULL;
}

static bool shutdown_health_management_thread(void *thread_data)
{
	int ret;
	int pipe_write_fd;
	struct lttng_pipe *health_quit_pipe = thread_data;

	pipe_write_fd = lttng_pipe_get_writefd(health_quit_pipe);
	ret = notify_thread_pipe(pipe_write_fd);
	if (ret < 0) {
		ERR("Failed to notify Health management thread's quit pipe");
		goto error;
	}
	return true;
error:
	return false;
}

bool launch_health_management_thread(void)
{
	struct lttng_thread *thread;
	struct lttng_pipe *health_quit_pipe = NULL;

	health_quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!health_quit_pipe) {
		goto error;
	}

	thread = lttng_thread_create("Health management",
			thread_manage_health,
			shutdown_health_management_thread,
			cleanup_health_management_thread,
			health_quit_pipe);
	if (!thread) {
		goto error;
	}
	lttng_thread_put(thread);
	return true;
error:
	cleanup_health_management_thread(health_quit_pipe);
	return false;
}
