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
#include <pthread.h>

#include "lttng-sessiond.h"
#include "health-sessiond.h"
#include "testpoint.h"
#include "utils.h"

int ht_cleanup_quit_pipe[2] = { -1, -1 };

/*
 * Check if the ht_cleanup thread quit pipe was triggered.
 *
 * Return true if it was triggered else false;
 */
static bool check_quit_pipe(int fd, uint32_t events)
{
	return (fd == ht_cleanup_quit_pipe[0] && (events & LPOLLIN));
}

static int init_pipe(int *pipe_fds)
{
	int ret, i;

	ret = pipe(pipe_fds);
	if (ret < 0) {
		PERROR("ht_cleanup thread quit pipe");
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = fcntl(pipe_fds[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl ht_cleanup_quit_pipe");
			goto error;
		}
	}
error:
	return ret;
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
static int set_pollset(struct lttng_poll_event *events, size_t size)
{
	int ret;

	ret = lttng_poll_create(events, size, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(events, ht_cleanup_quit_pipe[0],
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(events, ht_cleanup_pipe[0], LPOLLIN | LPOLLERR);
	if (ret < 0) {
		DBG("[ht-thread] lttng_poll_add error %d.", ret);
		goto error;
	}

	return 0;

error:
	return ret;
}

static void *thread_ht_cleanup(void *data)
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

	ret = set_pollset(&events, 2);
	if (ret < 0) {
		DBG("[ht-thread] sessiond_set_ht_cleanup_thread_pollset error %d.", ret);
		goto error_poll_create;
	}

	health_code_update();

	while (1) {
		DBG3("[ht-thread] Polling.");
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
				continue;
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
			ret = check_quit_pipe(pollfd, revents);
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

int init_ht_cleanup_thread(pthread_t *thread)
{
	int ret;

	ret = init_pipe(ht_cleanup_pipe);
	if (ret) {
		goto error;
	}

	ret = init_pipe(ht_cleanup_quit_pipe);
	if (ret) {
		goto error_quit_pipe;
	}

	ret = pthread_create(thread, default_pthread_attr(), thread_ht_cleanup,
			NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create ht_cleanup");
		goto error_thread;
	}

error:
	return ret;

error_thread:
	utils_close_pipe(ht_cleanup_quit_pipe);
error_quit_pipe:
	utils_close_pipe(ht_cleanup_pipe);
	return ret;
}

int fini_ht_cleanup_thread(pthread_t *thread)
{
	int ret;

	ret = notify_thread_pipe(ht_cleanup_quit_pipe[1]);
	if (ret < 0) {
		ERR("write error on ht_cleanup quit pipe");
		goto end;
	}

	ret = pthread_join(*thread, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_join ht cleanup thread");
	}
	utils_close_pipe(ht_cleanup_pipe);
	utils_close_pipe(ht_cleanup_quit_pipe);
end:
	return ret;
}
