/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef FD_TRACKER_UTILS_H
#define FD_TRACKER_UTILS_H

#include <common/fd-tracker/fd-tracker.h>

struct lttng_poll_event;

/*
 * Utility implementing a close_fd callback which receives one file descriptor
 * and closes it, returning close()'s return value.
 */
int fd_tracker_util_close_fd(void *, int *fd);

/*
 * Create a pipe and track its underlying fds.
 */
int fd_tracker_util_pipe_open_cloexec(struct fd_tracker *tracker,
		const char *name, int *pipe);
int fd_tracker_util_pipe_close(struct fd_tracker *tracker, int *pipe);

/*
 * Create a poll event and track its underlying fd, if applicable.
 */
int fd_tracker_util_poll_create(struct fd_tracker *tracker, const char *name,
		struct lttng_poll_event *events, int size, int flags);
int fd_tracker_util_poll_clean(struct fd_tracker *tracker,
		struct lttng_poll_event *events);

#endif /* FD_TRACKER_UTILS_H */
