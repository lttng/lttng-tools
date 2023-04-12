/*
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2011-2012 Matthew Khouzam <matthew.khouzam@ericsson.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_exitfast

#if !defined(_TRACEPOINT_UST_TESTS_EXITFAST_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_EXITFAST_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(ust_tests_exitfast,
		 message,
		 TP_ARGS(char *, text),
		 TP_FIELDS(ctf_string(message, text)))

TRACEPOINT_LOGLEVEL(ust_tests_exitfast, message, TRACE_INFO)

#endif /* _TRACEPOINT_UST_TESTS_EXITFAST_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_exitfast.h"

#include <lttng/tracepoint-event.h>
