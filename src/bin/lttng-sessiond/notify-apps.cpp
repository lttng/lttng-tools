/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "fd-limit.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "notify-apps.hpp"
#include "testpoint.hpp"
#include "thread.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/utils.hpp>

#include <fcntl.h>

namespace {
struct thread_notifiers {
	struct lttng_pipe *quit_pipe;
	int apps_cmd_notify_pipe_read_fd;
};
} /* namespace */

/*
 * This thread manage application notify communication.
 */
static void *thread_application_notification(void *data)
{
	int i, ret, err = -1;
	ssize_t size_ret;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	const auto thread_quit_pipe_fd = lttng_pipe_get_readfd(notifiers->quit_pipe);

	DBG("[ust-thread] Manage application notify command");

	rcu_register_thread();
	rcu_thread_online();

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_APP_MANAGE_NOTIFY);

	if (testpoint(sessiond_thread_app_manage_notify)) {
		goto error_testpoint;
	}

	health_code_update();

	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_poll_create;
	}

	/* Add notify pipe to the pollset. */
	ret = lttng_poll_add(
		&events, notifiers->apps_cmd_notify_pipe_read_fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(&events, thread_quit_pipe_fd, LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	while (true) {
		DBG3("[ust-thread] Manage notify polling");

		/* Inifinite blocking call, waiting for transmission */
	restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG3("[ust-thread] Manage notify return from poll on %d fds",
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
			health_code_update();

			/* Fetch once the poll data */
			const auto revents = LTTNG_POLL_GETEV(&events, i);
			const auto pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Activity on thread quit pipe, exiting. */
			if (pollfd == thread_quit_pipe_fd) {
				DBG("Activity on thread quit pipe");
				err = 0;
				goto exit;
			}

			if (pollfd == notifiers->apps_cmd_notify_pipe_read_fd) {
				/* Inspect the apps cmd pipe */
				int sock;

				if (revents & LPOLLIN) {
					/* Get socket from dispatch thread. */
					size_ret =
						lttng_read(notifiers->apps_cmd_notify_pipe_read_fd,
							   &sock,
							   sizeof(sock));
					if (size_ret < sizeof(sock)) {
						PERROR("read apps notify pipe");
						goto error;
					}
					health_code_update();

					ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLRDHUP);
					if (ret < 0) {
						/*
						 * It's possible we've reached the max poll fd
						 * allowed. Let's close the socket but continue
						 * normal execution.
						 */
						ret = close(sock);
						if (ret) {
							PERROR("close notify socket %d", sock);
						}
						lttng_fd_put(LTTNG_FD_APPS, 1);
						continue;
					}
					DBG3("UST thread notify added sock %d to pollset", sock);
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Apps notify command pipe error");
					goto error;
				} else {
					ERR("Unexpected poll events %u for sock %d",
					    revents,
					    pollfd);
					goto error;
				}
			} else {
				/*
				 * At this point, we know that a registered application
				 * triggered the event.
				 */
				if (revents & (LPOLLIN | LPOLLPRI)) {
					ret = ust_app_recv_notify(pollfd);
					if (ret < 0) {
						/* Removing from the poll set */
						ret = lttng_poll_del(&events, pollfd);
						if (ret < 0) {
							goto error;
						}

						/* The socket is closed after a grace period here.
						 */
						ust_app_notify_sock_unregister(pollfd);
					}
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					/* Removing from the poll set */
					ret = lttng_poll_del(&events, pollfd);
					if (ret < 0) {
						goto error;
					}

					/* The socket is closed after a grace period here. */
					ust_app_notify_sock_unregister(pollfd);
				} else {
					ERR("Unexpected poll events %u for sock %d",
					    revents,
					    pollfd);
					goto error;
				}
				health_code_update();
			}
		}
	}

exit:
error:
	lttng_poll_clean(&events);
error_poll_create:
error_testpoint:

	DBG("Application notify communication apps thread cleanup complete");
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(the_health_sessiond);
	rcu_thread_offline();
	rcu_unregister_thread();
	return nullptr;
}

static bool shutdown_application_notification_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	const int write_fd = lttng_pipe_get_writefd(notifiers->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

static void cleanup_application_notification_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;

	lttng_pipe_destroy(notifiers->quit_pipe);
	free(notifiers);
}

bool launch_application_notification_thread(int apps_cmd_notify_pipe_read_fd)
{
	struct lttng_thread *thread;
	struct thread_notifiers *notifiers;
	struct lttng_pipe *quit_pipe;

	notifiers = zmalloc<thread_notifiers>();
	if (!notifiers) {
		goto error_alloc;
	}
	notifiers->apps_cmd_notify_pipe_read_fd = apps_cmd_notify_pipe_read_fd;

	quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!quit_pipe) {
		goto error;
	}
	notifiers->quit_pipe = quit_pipe;

	thread = lttng_thread_create("Application notification",
				     thread_application_notification,
				     shutdown_application_notification_thread,
				     cleanup_application_notification_thread,
				     notifiers);
	if (!thread) {
		goto error;
	}
	lttng_thread_put(thread);
	return true;
error:
	cleanup_application_notification_thread(notifiers);
error_alloc:
	return false;
}
