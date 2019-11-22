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

/*
 * The epoll variant of the poll compat layer creates an unsuspendable fd which
 * must be tracked.
 */
int fd_tracker_util_poll_create(struct fd_tracker *tracker, const char *name,
		struct lttng_poll_event *events, int size, int flags)
{
	return lttng_poll_create(events, size, flags);
}

int fd_tracker_util_poll_clean(struct fd_tracker *tracker,
		struct lttng_poll_event *events)
{
	lttng_poll_clean(events);
	return 0;
}
