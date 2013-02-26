/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define _GNU_SOURCE
#include <assert.h>

#include <common/common.h>
#include <common/utils.h>

#include "fd-limit.h"
#include "lttng-sessiond.h"
#include "ust-thread.h"

/*
 * This thread manage application notify communication.
 */
void *ust_thread_manage_notify(void *data)
{
	int i, ret, pollfd;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;

	DBG("[ust-thread] Manage application notify command");

	rcu_register_thread();
	rcu_thread_online();

	ret = sessiond_set_thread_pollset(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	/* Add notify pipe to the pollset. */
	ret = lttng_poll_add(&events, apps_cmd_notify_pipe[0], LPOLLIN | LPOLLERR);
	if (ret < 0) {
		goto error;
	}

	while (1) {
		DBG3("[ust-thread] Manage notify polling on %d fds",
				LTTNG_POLL_GETNB(&events));

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
			ret = sessiond_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				goto exit;
			}

			/* Inspect the apps cmd pipe */
			if (pollfd == apps_cmd_notify_pipe[0]) {
				int sock;

				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Apps notify command pipe error");
					goto error;
				} else if (!(revents & LPOLLIN)) {
					/* No POLLIN and not a catched error, stop the thread. */
					ERR("Notify command pipe failed. revent: %u", revents);
					goto error;
				}

				do {
					/* Get socket from dispatch thread. */
					ret = read(apps_cmd_notify_pipe[0], &sock, sizeof(sock));
				} while (ret < 0 && errno == EINTR);
				if (ret < 0 || ret < sizeof(sock)) {
					PERROR("read apps notify pipe");
					goto error;
				}

				ret = lttng_poll_add(&events, sock,
						LPOLLIN | LPOLLERR | LPOLLHUP | LPOLLRDHUP);
				if (ret < 0) {
					/*
					 * It's possible we've reached the max poll fd allowed.
					 * Let's close the socket but continue normal execution.
					 */
					ret = close(sock);
					if (ret) {
						PERROR("close notify socket %d", sock);
					}
					lttng_fd_put(LTTNG_FD_APPS, 1);
					continue;
				}
				DBG3("UST thread notify added sock %d to pollset", sock);
			} else {
				/*
				 * At this point, we know that a registered application
				 * triggered the event.
				 */
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					/* Removing from the poll set */
					ret = lttng_poll_del(&events, pollfd);
					if (ret < 0) {
						goto error;
					}

					/* The socket is closed after a grace period here. */
					ust_app_notify_sock_unregister(pollfd);
				} else if (revents & (LPOLLIN | LPOLLPRI)) {
					ret = ust_app_recv_notify(pollfd);
					if (ret < 0) {
						/*
						 * If the notification failed either the application is
						 * dead or an internal error happened. In both cases,
						 * we can only continue here. If the application is
						 * dead, an unregistration will follow or else the
						 * application will notice that we are not responding
						 * on that socket and will close it.
						 */
						continue;
					}
				} else {
					ERR("Unknown poll events %u for sock %d", revents, pollfd);
					continue;
				}
			}
		}
	}

exit:
error:
	lttng_poll_clean(&events);
error_poll_create:
	utils_close_pipe(apps_cmd_notify_pipe);
	apps_cmd_notify_pipe[0] = apps_cmd_notify_pipe[1] = -1;
	DBG("Application notify communication apps thread cleanup complete");
	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}
