/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "health-sessiond.hpp"
#include "manage-apps.hpp"
#include "testpoint.hpp"
#include "thread.hpp"
#include "utils.hpp"

#include <fcntl.h>

namespace {
struct thread_notifiers {
	struct lttng_pipe *quit_pipe;
	int apps_cmd_pipe_read_fd;
};
} /* namespace */

static void cleanup_application_management_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;

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
 * associated data structures through ust_app_unregister_by_socket().
 *
 * Note that this thread never sends commands to the applications
 * through the command sockets; it merely listens for hang-ups
 * and errors on those sockets and cleans-up as they occur.
 */
static void *thread_application_management(void *data)
{
	int i, ret, err = -1;
	ssize_t size_ret;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	const auto thread_quit_pipe_fd = lttng_pipe_get_readfd(notifiers->quit_pipe);

	DBG("[thread] Manage application started");

	rcu_register_thread();
	rcu_thread_online();

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_APP_MANAGE);

	if (testpoint(sessiond_thread_manage_apps)) {
		goto error_testpoint;
	}

	health_code_update();

	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, notifiers->apps_cmd_pipe_read_fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(&events, thread_quit_pipe_fd, LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	if (testpoint(sessiond_thread_manage_apps_before_loop)) {
		goto error;
	}

	health_code_update();

	while (true) {
		DBG("Apps thread polling");

		/* Inifinite blocking call, waiting for transmission */
	restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG("Apps thread return from poll on %d fds", LTTNG_POLL_GETNB(&events));
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
			const auto revents = LTTNG_POLL_GETEV(&events, i);
			const auto pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			/* Activity on thread quit pipe, exiting. */
			if (pollfd == thread_quit_pipe_fd) {
				DBG("Activity on thread quit pipe");
				err = 0;
				goto exit;
			}

			if (pollfd == notifiers->apps_cmd_pipe_read_fd) {
				/* Inspect the apps cmd pipe */
				if (revents & LPOLLIN) {
					int sock;

					/* Empty pipe */
					size_ret = lttng_read(notifiers->apps_cmd_pipe_read_fd,
							      &sock,
							      sizeof(sock));
					if (size_ret < sizeof(sock)) {
						PERROR("read apps cmd pipe");
						goto error;
					}

					health_code_update();

					/*
					 * Since this is a command socket (write then read),
					 * we only monitor the error events of the socket.
					 */
					ret = lttng_poll_add(&events, sock, LPOLLRDHUP);
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
					ust_app_unregister_by_socket(pollfd);
				} else {
					ERR("Unexpected poll events %u for sock %d",
					    revents,
					    pollfd);
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
	health_unregister(the_health_sessiond);
	DBG("Application communication apps thread cleanup complete");
	rcu_thread_offline();
	rcu_unregister_thread();
	return nullptr;
}

static bool shutdown_application_management_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	const int write_fd = lttng_pipe_get_writefd(notifiers->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

bool launch_application_management_thread(int apps_cmd_pipe_read_fd)
{
	struct lttng_pipe *quit_pipe;
	struct thread_notifiers *notifiers = nullptr;
	struct lttng_thread *thread;

	notifiers = zmalloc<thread_notifiers>();
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
