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
#include <stddef.h>
#include <common/sessiond-comm/sessiond-comm.h>

int lttng_event_get_filter_expression(struct lttng_event *event,
	const char **filter_expression)
{
	int ret = 0;
	struct lttcomm_event_extended_header *ext_header;

	if (!event || !filter_expression) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ext_header = event->extended.ptr;

	if (!ext_header) {
		/*
		 * This can happen since the lttng_event structure is
		 * used for other tasks where this pointer is never set.
		 */
		*filter_expression = NULL;
		goto end;
	}

	if (ext_header->filter_len) {
		*filter_expression = ((const char *) (ext_header)) +
				sizeof(*ext_header);
	} else {
		*filter_expression = NULL;
	}

end:
	return ret;
}

int lttng_event_get_exclusion_name_count(struct lttng_event *event)
{
	int ret;
	struct lttcomm_event_extended_header *ext_header;

	if (!event) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ext_header = event->extended.ptr;
	if (!ext_header) {
		/*
		 * This can happen since the lttng_event structure is
		 * used for other tasks where this pointer is never set.
		 */
		ret = 0;
		goto end;
	}

	if (ext_header->nb_exclusions > INT_MAX) {
		ret = -LTTNG_ERR_OVERFLOW;
		goto end;
	}
	ret = (int) ext_header->nb_exclusions;
end:
	return ret;
}

int lttng_event_get_exclusion_name(struct lttng_event *event,
		size_t index, const char **exclusion_name)
{
	int ret = 0;
	struct lttcomm_event_extended_header *ext_header;
	void *at;

	if (!event || !exclusion_name) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	ext_header = event->extended.ptr;
	if (!ext_header) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	if (index >= ext_header->nb_exclusions) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	at = (void *) ext_header + sizeof(*ext_header);
	at += ext_header->filter_len;
	at += index * LTTNG_SYMBOL_NAME_LEN;
	*exclusion_name = at;

end:
	return ret;
}
