/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/compat/poll.h>

#include "utils.h"

/*
 * The epoll variant of the poll compat layer creates an unsuspendable fd which
 * must be tracked.
 */
int fd_tracker_util_poll_create(struct fd_tracker *tracker,
		const char *name,
		struct lttng_poll_event *events,
		int size,
		int flags)
{
	return lttng_poll_create(events, size, flags);
}

int fd_tracker_util_poll_clean(
		struct fd_tracker *tracker, struct lttng_poll_event *events)
{
	lttng_poll_clean(events);
	return 0;
}
