/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef FD_TRACKER_UTILS_H
#define FD_TRACKER_UTILS_H

#include <common/compat/directory-handle.hpp>
#include <common/compat/poll.hpp>
#include <common/fd-tracker/fd-tracker.hpp>
#include <common/macros.hpp>

/*
 * Utility implementing a close_fd callback which receives one file descriptor
 * and closes it, returning close()'s return value.
 */
int fd_tracker_util_close_fd(void *, int *fd);

/*
 * Create a pipe and track its underlying fds.
 */
int fd_tracker_util_pipe_open_cloexec(struct fd_tracker *tracker, const char *name, int *pipe);
int fd_tracker_util_pipe_close(struct fd_tracker *tracker, int *pipe);

/*
 * Create a poll event and track its underlying fd, if applicable.
 */
int fd_tracker_util_poll_create(struct fd_tracker *tracker,
				const char *name,
				struct lttng_poll_event *events,
				int size,
				int flags);
int fd_tracker_util_poll_clean(struct fd_tracker *tracker, struct lttng_poll_event *events);

struct lttng_directory_handle *fd_tracker_create_directory_handle(struct fd_tracker *tracker,
								  const char *path);

struct lttng_directory_handle *fd_tracker_create_directory_handle_from_handle(
	struct fd_tracker *tracker, struct lttng_directory_handle *handle, const char *path);

#endif /* FD_TRACKER_UTILS_H */
