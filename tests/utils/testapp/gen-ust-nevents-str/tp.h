#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp

#if !defined(_TRACEPOINT_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_H

/*
 * Copyright (C) - 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(tp, the_string,
	TP_ARGS(
		int, i,
		int, arg_i,
		const char *, str
	),
	TP_FIELDS(
		ctf_integer(int, i, i)
		ctf_integer(long, arg_i, arg_i)
		ctf_string(str, str)
	)
)

#endif /* _TRACEPOINT_TP_H */

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./tp.h

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
