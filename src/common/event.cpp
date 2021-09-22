/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/event-internal.h>
#include <common/error.h>

struct lttng_event *lttng_event_copy(const struct lttng_event *event)
{
	struct lttng_event *new_event;
	struct lttng_event_extended *new_event_extended;

	new_event = (lttng_event *) zmalloc(sizeof(*event));
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
	new_event_extended = (lttng_event_extended *) zmalloc(sizeof(*new_event_extended));
	if (!new_event_extended) {
		PERROR("Error allocating event extended structure");
		goto error;
	}

	new_event->extended.ptr = new_event_extended;
end:
	return new_event;
error:
	free(new_event);
	new_event = NULL;
	goto end;
}
