/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <lttng/event-internal.h>
#include <common/error.h>

LTTNG_HIDDEN
struct lttng_event *lttng_event_copy(const struct lttng_event *event)
{
	struct lttng_event *new_event;
	struct lttng_event_extended *new_event_extended;

	new_event = zmalloc(sizeof(*event));
	if (!new_event) {
		PERROR("Error allocating event structure");
		goto end;
	}

	/* Copy the content of the old event. */
	memcpy(new_event, event, sizeof(*event));

	/*
	 * We need to create a new extended since the previous pointer is now
	 * invalid.
	 */
	new_event_extended = zmalloc(sizeof(*new_event_extended));
	if (!new_event_extended) {
		PERROR("Error allocating event extended structure");
		goto error;
	}

	new_event->extended.ptr = new_event_extended;
end:
	return new_event;
error:
	free(new_event);
	goto end;
}
