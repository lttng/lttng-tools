/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-sessiond.hpp"
#include "utils.hpp"

#include <common/utils.hpp>

#include <fcntl.h>
#include <pthread.h>

/*
 * Quit pipe for the main thread. This is used by signal handlers to start the
 * shutdown sequence of the main thread which will tear down the other threads
 * in the appropriate order.
 */
static int main_quit_pipe[2] = { -1, -1 };

/*
 * Init main quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
int sessiond_init_main_quit_pipe()
{
	int ret, i;

	ret = pipe(main_quit_pipe);
	if (ret < 0) {
		PERROR("main quit pipe");
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = fcntl(main_quit_pipe[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl main_quit_pipe");
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Wait for a notification on the main quit pipe (with a timeout).
 *
 * A timeout value of -1U means no timeout.
 *
 * Returns 1 if the caller should quit, 0 if the timeout was reached, and
 * -1 if an error was encountered.
 */
int sessiond_wait_for_main_quit_pipe(int timeout_ms)
{
	int ret;
	struct lttng_poll_event events;

	ret = lttng_poll_create(&events, 1, LTTNG_CLOEXEC);
	if (ret < 0) {
		PERROR("Failed to initialize poll/epoll set");
		ret = -1;
		goto end;
	}
	ret = lttng_poll_add(&events, main_quit_pipe[0], LPOLLIN);
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
		PERROR("Failed to epoll()/poll() main quit pipe");
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

int sessiond_notify_main_quit_pipe()
{
	return notify_thread_pipe(main_quit_pipe[1]);
}

void sessiond_close_main_quit_pipe()
{
	utils_close_pipe(main_quit_pipe);
}

/*
 * Create a poll set with O_CLOEXEC and add the main quit pipe to the set.
 */
int sessiond_set_thread_pollset(struct lttng_poll_event *events, size_t size)
{
	int ret;

	LTTNG_ASSERT(events);

	ret = lttng_poll_create(events, size, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	/* Add main quit pipe */
	ret = lttng_poll_add(events, main_quit_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	return ret;
}
