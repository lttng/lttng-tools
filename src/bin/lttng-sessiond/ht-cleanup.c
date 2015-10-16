/*
 * Copyright (C) 2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _LGPL_SOURCE
#include <assert.h>

#include <common/hashtable/hashtable.h>
#include <common/common.h>
#include <common/utils.h>

#include "lttng-sessiond.h"
#include "health-sessiond.h"
#include "testpoint.h"

void *thread_ht_cleanup(void *data)
{
	int ret, i, pollfd, err = -1;
	ssize_t size_ret;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;

	DBG("[ht-thread] startup.");

	rcu_register_thread();
	rcu_thread_online();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_HT_CLEANUP);

	if (testpoint(sessiond_thread_ht_cleanup)) {
		DBG("[ht-thread] testpoint.");
		goto error_testpoint;
	}

	health_code_update();

	ret = sessiond_set_ht_cleanup_thread_pollset(&events, 2);
	if (ret < 0) {
		DBG("[ht-thread] sessiond_set_ht_cleanup_thread_pollset error %d.", ret);
		goto error_poll_create;
	}

	/* Add pipe to the pollset. */
	ret = lttng_poll_add(&events, ht_cleanup_pipe[0], LPOLLIN | LPOLLERR);
	if (ret < 0) {
		DBG("[ht-thread] lttng_poll_add error %d.", ret);
		goto error;
	}

	health_code_update();

	while (1) {
		DBG3("[ht-thread] Polling.");

		/* Inifinite blocking call, waiting for transmission */
restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG3("[ht-thread] Returning from poll on %d fds.",
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
			struct lttng_ht *ht;

			health_code_update();

			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			if (pollfd != ht_cleanup_pipe[0]) {
				continue;
			}

			if (revents & LPOLLIN) {
				/* Get socket from dispatch thread. */
				size_ret = lttng_read(ht_cleanup_pipe[0], &ht,
						sizeof(ht));
				if (size_ret < sizeof(ht)) {
					PERROR("ht cleanup notify pipe");
					goto error;
				}
				health_code_update();
				/*
				 * The whole point of this thread is to call
				 * lttng_ht_destroy from a context that is NOT:
				 * 1) a read-side RCU lock,
				 * 2) a call_rcu thread.
				 */
				lttng_ht_destroy(ht);

				health_code_update();
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("ht cleanup pipe error");
				goto error;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
			}
		}

		for (i = 0; i < nb_fd; i++) {
			health_code_update();

			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			if (pollfd == ht_cleanup_pipe[0]) {
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = sessiond_check_ht_cleanup_quit(pollfd, revents);
			if (ret) {
				err = 0;
				DBG("[ht-cleanup] quit.");
				goto exit;
			}
		}
	}

exit:
error:
	lttng_poll_clean(&events);
error_poll_create:
error_testpoint:
	DBG("[ht-cleanup] Thread terminates.");
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_sessiond);
	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}
