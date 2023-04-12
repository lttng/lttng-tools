/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_demo3

#if !defined(_TRACEPOINT_UST_TESTS_DEMO3_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_DEMO3_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(ust_tests_demo3,
		 done,
		 TP_ARGS(int, value),
		 TP_FIELDS(ctf_integer(int, value, value)))
TRACEPOINT_LOGLEVEL(ust_tests_demo3, done, TRACE_WARNING)

#endif /* _TRACEPOINT_UST_TESTS_DEMO3_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_demo3.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
