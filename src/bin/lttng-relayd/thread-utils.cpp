/*
 * Copyright (C) 2022 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-relayd.hpp"

#include <common/compat/poll.hpp>
#include <common/error.hpp>
#include <common/fd-tracker/utils.hpp>
#include <common/readwrite.hpp>
#include <common/utils.hpp>

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
static int thread_quit_pipe[2] = { -1, -1 };

/*
 * Write to writable pipe used to notify a thread.
 */
static int notify_thread_pipe(int wpipe)
{
	const auto ret = lttng_write(wpipe, "!", 1);

	if (ret < 1) {
		PERROR("Failed to write to thread pipe");
		return -1;
	}

	return 0;
}

/*
 * Initialize the thread quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
int relayd_init_thread_quit_pipe(void)
{
	return fd_tracker_util_pipe_open_cloexec(
			the_fd_tracker, "Thread quit pipe", thread_quit_pipe);
}

/*
 * Notify the threads to initiate shutdown.
 *
 * Return 0 on success or -1 on error.
 */
int relayd_notify_thread_quit_pipe(void)
{
	return notify_thread_pipe(thread_quit_pipe[1]);
}

/*
 * Close the thread quit pipe.
 */
void relayd_close_thread_quit_pipe(void)
{
	if (thread_quit_pipe[0] != -1) {
		(void) fd_tracker_util_pipe_close(
				the_fd_tracker, thread_quit_pipe);
	}
}

/*
 * Return 1 if 'fd' is the thread quit pipe read fd.
 */
bool relayd_is_thread_quit_pipe(const int fd)
{
	return (fd == thread_quit_pipe[0]);
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
int create_named_thread_poll_set(struct lttng_poll_event *events,
		int size, const char *name)
{
	if (events == NULL || size == 0) {
		return -1;
	}

	const auto create_ret = fd_tracker_util_poll_create(the_fd_tracker,
			name, events, 1, LTTNG_CLOEXEC);
	if (create_ret) {
		PERROR("Failed to create \"%s\" poll file descriptor", name);
		return -1;
	}

	/* Add thread quit pipe to monitored events. */
	const auto poll_add_ret = lttng_poll_add(events, thread_quit_pipe[0], LPOLLIN | LPOLLERR);
	if (poll_add_ret < 0) {
		return -1;
	}

	return 0;
}
