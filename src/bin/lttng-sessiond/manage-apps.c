/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "manage-apps.h"
#include "testpoint.h"
#include "health-sessiond.h"
#include "utils.h"
#include "thread.h"

struct thread_notifiers {
	struct lttng_pipe *quit_pipe;
	int apps_cmd_pipe_read_fd;
};

static void cleanup_application_management_thread(void *data)
{
	struct thread_notifiers *notifiers = data;

	lttng_pipe_destroy(notifiers->quit_pipe);
	free(notifiers);
}

/*
 * This thread receives application command sockets (FDs) on the
 * apps_cmd_pipe and waits (polls) on them until they are closed
 * or an error occurs.
 *
 * At that point, it flushes the data (tracing and metadata) associated
 * with this application and tears down ust app sessions and other
 * associated data structures through ust_app_unregister().
 *
 * Note that this thread never sends commands to the applications
 * through the command sockets; it merely listens for hang-ups
 * and errors on those sockets and cleans-up as they occur.
 */
static void *thread_application_management(void *data)
{
	int i, ret, pollfd, err = -1;
	ssize_t size_ret;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct thread_notifiers *notifiers = data;
	const int quit_pipe_read_fd = lttng_pipe_get_readfd(
			notifiers->quit_pipe);

	DBG("[thread] Manage application started");

	rcu_register_thread();
	rcu_thread_online();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_APP_MANAGE);

	if (testpoint(sessiond_thread_manage_apps)) {
		goto error_testpoint;
	}

	health_code_update();

	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, notifiers->apps_cmd_pipe_read_fd,
			LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(&events, quit_pipe_read_fd, LPOLLIN | LPOLLERR);
	if (ret < 0) {
		goto error;
	}

	if (testpoint(sessiond_thread_manage_apps_before_loop)) {
		goto error;
	}

	health_code_update();

	while (1) {
		DBG("Apps thread polling");

		/* Inifinite blocking call, waiting for transmission */
	restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG("Apps thread return from poll on %d fds",
				LTTNG_POLL_GETNB(&events));
		health_poll_exit();
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

			health_code_update();

			if (pollfd == quit_pipe_read_fd) {
				err = 0;
				goto exit;
			} else if (pollfd == notifiers->apps_cmd_pipe_read_fd) {
				/* Inspect the apps cmd pipe */
				if (revents & LPOLLIN) {
					int sock;

					/* Empty pipe */
					size_ret = lttng_read(
							notifiers->apps_cmd_pipe_read_fd,
							&sock, sizeof(sock));
					if (size_ret < sizeof(sock)) {
						PERROR("read apps cmd pipe");
						goto error;
					}

					health_code_update();

					/*
					 * Since this is a command socket (write then read),
					 * we only monitor the error events of the socket.
					 */
					ret = lttng_poll_add(&events, sock,
							LPOLLERR | LPOLLHUP | LPOLLRDHUP);
					if (ret < 0) {
						goto error;
					}

					DBG("Apps with sock %d added to poll set", sock);
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Apps command pipe error");
					goto error;
				} else {
					ERR("Unknown poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			} else {
				/*
				 * At this point, we know that a registered application made
				 * the event at poll_wait.
				 */
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					/* Removing from the poll set */
					ret = lttng_poll_del(&events, pollfd);
					if (ret < 0) {
						goto error;
					}

					/* Socket closed on remote end. */
					ust_app_unregister(pollfd);
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			}

			health_code_update();
		}
	}

exit:
error:
	lttng_poll_clean(&events);
error_poll_create:
error_testpoint:

	/*
	 * We don't clean the UST app hash table here since already registered
	 * applications can still be controlled so let them be until the session
	 * daemon dies or the applications stop.
	 */

	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_sessiond);
	DBG("Application communication apps thread cleanup complete");
	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}

static bool shutdown_application_management_thread(void *data)
{
	struct thread_notifiers *notifiers = data;
	const int write_fd = lttng_pipe_get_writefd(notifiers->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

bool launch_application_management_thread(int apps_cmd_pipe_read_fd)
{
	struct lttng_pipe *quit_pipe;
	struct thread_notifiers *notifiers = NULL;
	struct lttng_thread *thread;

	notifiers = zmalloc(sizeof(*notifiers));
	if (!notifiers) {
		goto error_alloc;
	}
	quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!quit_pipe) {
		goto error;
	}
	notifiers->quit_pipe = quit_pipe;
	notifiers->apps_cmd_pipe_read_fd = apps_cmd_pipe_read_fd;

	thread = lttng_thread_create("UST application management",
			thread_application_management,
			shutdown_application_management_thread,
			cleanup_application_management_thread,
			notifiers);
	if (!thread) {
		goto error;
	}

	lttng_thread_put(thread);
	return true;
error:
	cleanup_application_management_thread(notifiers);
error_alloc:
	return false;
}
