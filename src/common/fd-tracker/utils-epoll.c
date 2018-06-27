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

#include <common/compat/poll.h>

#include "utils.h"

struct create_args {
	struct lttng_poll_event *events;
	int size;
	int flags;
};

static
int open_epoll(void *data, int *out_fd)
{
	int ret;
	struct create_args *args = data;

	ret = lttng_poll_create(args->events, args->size, args->flags);
	if (ret < 0) {
		goto end;
	}

	*out_fd = args->events->epfd;
end:
	return ret;
}

static
int close_epoll(void *data, int *in_fd)
{
	/* Will close the epfd. */
	lttng_poll_clean((struct lttng_poll_event *) data);
	return 0;
}

/*
 * The epoll variant of the poll compat layer creates an unsuspendable fd which
 * must be tracked.
 */
int fd_tracker_util_poll_create(struct fd_tracker *tracker, const char *name,
		struct lttng_poll_event *events, int size, int flags)
{
	int out_fd;
	struct create_args create_args = {
		.events = events,
		.size = size,
		.flags = flags,
	};

	return fd_tracker_open_unsuspendable_fd(tracker, &out_fd, &name, 1,
			open_epoll, &create_args);
}

int fd_tracker_util_poll_clean(struct fd_tracker *tracker,
		struct lttng_poll_event *events)
{
	return fd_tracker_close_unsuspendable_fd(tracker, &events->epfd, 1,
			close_epoll, events);
}
