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

#include "lttng-sessiond.h"
#include "utils.h"
#include <common/utils.h>

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
static int thread_quit_pipe[2] = { -1, -1 };

/*
 * Init thread quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
static int __init_thread_quit_pipe(int *a_pipe)
{
	int ret, i;

	ret = pipe(a_pipe);
	if (ret < 0) {
		PERROR("thread quit pipe");
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = fcntl(a_pipe[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl");
			goto error;
		}
	}

error:
	return ret;
}

int sessiond_init_thread_quit_pipe(void)
{
	return __init_thread_quit_pipe(thread_quit_pipe);
}

int sessiond_check_thread_quit_pipe(int fd, uint32_t events)
{
	return (fd == thread_quit_pipe[0] && (events & LPOLLIN));
}

/*
 * Wait for a notification on the quit pipe (with a timeout).
 *
 * Returns 1 if the caller should quit, 0 if the timeout was reached, and
 * -1 if an error was encountered.
 */
int sessiond_wait_for_quit_pipe(unsigned int timeout_us)
{
	int ret;
	fd_set read_fds;
	struct timeval timeout;

	FD_ZERO(&read_fds);
	FD_SET(thread_quit_pipe[0], &read_fds);
	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_usec = timeout_us;

	while (true) {
		ret = select(thread_quit_pipe[0] + 1, &read_fds, NULL, NULL,
				&timeout);
		if (ret < 0 && errno == EINTR) {
			/* Retry on interrupt. */
			continue;
		} else {
			break;
		}
	}

	if (ret > 0) {
		/* Should quit. */
		ret = 1;
	} else if (ret < 0 && errno != EINTR) {
		/* Unknown error. */
		PERROR("Failed to select() thread quit pipe");
		ret = -1;
	} else {
		/* Timeout reached. */
		ret = 0;
	}

	return ret;
}

int sessiond_notify_quit_pipe(void)
{
	return notify_thread_pipe(thread_quit_pipe[1]);
}

void sessiond_close_quit_pipe(void)
{
	utils_close_pipe(thread_quit_pipe);
}

static
int __sessiond_set_thread_pollset(struct lttng_poll_event *events, size_t size,
		int *a_pipe)
{
	int ret;

	assert(events);

	ret = lttng_poll_create(events, size, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	/* Add quit pipe */
	ret = lttng_poll_add(events, a_pipe[0], LPOLLIN | LPOLLERR);
	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
int sessiond_set_thread_pollset(struct lttng_poll_event *events, size_t size)
{
	return __sessiond_set_thread_pollset(events, size, thread_quit_pipe);
}
