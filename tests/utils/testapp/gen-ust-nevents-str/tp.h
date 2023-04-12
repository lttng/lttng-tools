#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp

#if !defined(_TRACEPOINT_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_H

/*
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(tp,
		 the_string,
		 TP_ARGS(int, i, int, arg_i, const char *, str),
		 TP_FIELDS(ctf_integer(int, i, i) ctf_integer(long, arg_i, arg_i)
				   ctf_string(str, str)))

#endif /* _TRACEPOINT_TP_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
