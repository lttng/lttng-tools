/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-sessiond.h"
#include "utils.h"
#include <common/utils.h>
#include <pthread.h>

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
 * A timeout value of -1U means no timeout.
 *
 * Returns 1 if the caller should quit, 0 if the timeout was reached, and
 * -1 if an error was encountered.
 */
int sessiond_wait_for_quit_pipe(int timeout_ms)
{
	int ret;
	struct lttng_poll_event events;

	ret = lttng_poll_create(&events, 1, LTTNG_CLOEXEC);
	if (ret < 0) {
		PERROR("Failed to initialize poll/epoll set");
		ret = -1;
		goto end;
	}
	ret = lttng_poll_add(&events, thread_quit_pipe[0], LPOLLIN | LPOLLERR);
	if (ret < 0) {
		PERROR("Failed to add file descriptor to poll/epoll set");
		ret = -1;
		goto end_clean_poll;
	}
	ret = lttng_poll_wait(&events, timeout_ms);
	if (ret > 0) {
		/* Should quit. */
		ret = 1;
	} else if (ret < 0 && errno != EINTR) {
		/* Unknown error. */
		PERROR("Failed to epoll()/poll() thread quit pipe");
		ret = -1;
	} else {
		/* Timeout reached. */
		ret = 0;
	}
end_clean_poll:
	lttng_poll_clean(&events);
end:
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
