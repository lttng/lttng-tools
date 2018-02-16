/*
 * event.c
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _LGPL_SOURCE
#include <lttng/event.h>
#include <lttng/lttng-error.h>
#include <lttng/userspace-probe-internal.h>
#include <lttng/event-internal.h>
#include <stddef.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <assert.h>

struct lttng_event *lttng_event_create(void)
{
	struct lttng_event *event;
	struct lttng_event_extended *event_extended;

	event = zmalloc(sizeof(*event));
	if (!event) {
		goto end;
	}

	event_extended = zmalloc(sizeof(*event_extended));
	if (!event_extended) {
		goto error;
	}
	event->extended.ptr = event_extended;
end:
	return event;
error:
	free(event);
	goto end;
}

struct lttng_event *lttng_event_copy(struct lttng_event *event)
{
	struct lttng_event *new_event;
	struct lttng_event_extended *new_event_extended;

	new_event = zmalloc(sizeof(*event));
	if (!event) {
		goto end;
	}

	/* Copy the content of the old event */
	memcpy(new_event, event, sizeof(*event));

	/*
	 * We need to create a new extended since the previous pointer is now
	 * invalid
	 */
	new_event_extended = zmalloc(sizeof(*new_event_extended));
	if (!new_event_extended) {
		goto error;
	}

	new_event->extended.ptr = new_event_extended;
end:
	return new_event;
error:
	free(event);
	goto end;
}

void lttng_event_destroy(struct lttng_event *event)
{
	struct lttng_event_extended *event_extended;

	if (!event) {
		return;
	}

	event_extended = (struct lttng_event_extended *) event->extended.ptr;
	if (event_extended && event_extended->probe_location) {
		lttng_userspace_probe_location_destroy(
			event_extended->probe_location);
	}
	free(event);
}

int lttng_event_get_filter_expression(struct lttng_event *event,
	const char **filter_expression)
{
	int ret = 0;
	struct lttng_event_extended *event_extended;

	if (!event || !filter_expression) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	event_extended = (struct lttng_event_extended *) event->extended.ptr;
	if (!event_extended) {
		/*
		 * This can happen since the lttng_event structure is
		 * used for other tasks where this pointer is never set.
		 */
		*filter_expression = NULL;
		goto end;
	}

	*filter_expression = event_extended->filter_expression;
end:
	return ret;
}

int lttng_event_get_exclusion_name_count(struct lttng_event *event)
{
	int ret = 0;
	struct lttng_event_extended *event_extended;

	if (!event) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	event_extended = (struct lttng_event_extended *) event->extended.ptr;
	if (!event_extended) {
		/*
		 * This can happen since the lttng_event structure is
		 * used for other tasks where this pointer is never set.
		 */
		goto end;
	}

	if (event_extended->exclusions.count > INT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}
	ret = (int) event_extended->exclusions.count;
end:
	return ret;
}

int lttng_event_get_exclusion_name(struct lttng_event *event,
		size_t index, const char **exclusion_name)
{
	int ret = 0;
	struct lttng_event_extended *event_extended;

	if (!event || !exclusion_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (index > UINT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}

	event_extended = (struct lttng_event_extended *) event->extended.ptr;
	if (!event_extended) {
		/*
		 * This can happen since the lttng_event structure is
		 * used for other tasks where this pointer is never set.
		 */
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (index >= event_extended->exclusions.count) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	*exclusion_name = event_extended->exclusions.strings +
		(index * LTTNG_SYMBOL_NAME_LEN);
end:
	return ret;
}

struct lttng_userspace_probe_location *
lttng_event_get_userspace_probe_location(struct lttng_event *event)
{
	struct lttng_userspace_probe_location *probe_location = NULL;
	struct lttng_event_extended *event_extended;

	if (!event) {
		goto end;
	}

	event_extended = (struct lttng_event_extended *) event->extended.ptr;
	if (!event_extended) {
		goto end;
	}
	probe_location = event_extended->probe_location;
end:
	return probe_location;
}

int lttng_event_set_userspace_probe_location(struct lttng_event *event,
		struct lttng_userspace_probe_location *probe_location)
{
	int ret = 0;
	struct lttng_event_extended *event_extended;

	if (!event || !probe_location) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	event_extended = (struct lttng_event_extended *) event->extended.ptr;
	assert(event_extended);
	if (event_extended->probe_location) {
		lttng_userspace_probe_location_destroy(
			event_extended->probe_location);
	}
	event_extended->probe_location = probe_location;
end:
	return ret;
}
