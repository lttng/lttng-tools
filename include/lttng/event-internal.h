/*
 * event-internal.h
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

#ifndef LTTNG_EVENT_INTERNAL_H
#define LTTNG_EVENT_INTERNAL_H

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

#endif /* LTTNG_EVENT_INTERNAL_H */
