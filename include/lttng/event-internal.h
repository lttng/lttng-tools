/*
 * event-internal.h
 *
 * Linux Trace Toolkit Control Library
 *
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_INTERNAL_H
#define LTTNG_EVENT_INTERNAL_H

#include <common/macros.h>
#include <lttng/event.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_userspace_probe_location;

struct lttng_event_extended {
	/*
	 * exclusions and filter_expression are only set when the lttng_event
	 * was created/allocated by a list operation. These two elements must
	 * not be free'd as they are part of the same contiguous buffer that
	 * contains all events returned by the listing.
	 */
	char *filter_expression;
	struct {
		unsigned int count;
		/* Array of strings of fixed LTTNG_SYMBOL_NAME_LEN length. */
		char *strings;
	} exclusions;
	struct lttng_userspace_probe_location *probe_location;
};

struct lttng_event *lttng_event_copy(const struct lttng_event *event);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_INTERNAL_H */
