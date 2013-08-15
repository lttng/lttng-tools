#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_demo

#if !defined(_TRACEPOINT_UST_TESTS_DEMO_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_DEMO_H

/*
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(ust_tests_demo, starting,
	TP_ARGS(int, value),
	TP_FIELDS(
		ctf_integer(int, value, value)
	)
)
TRACEPOINT_LOGLEVEL(ust_tests_demo, starting, TRACE_CRIT)

/*
 * Dummy model information, just for example. TODO: we should check if
 * EMF model URI have some standard format we should follow.
 */
TRACEPOINT_MODEL_EMF_URI(ust_tests_demo, starting,
	"http://example.com/path_to_model?q=ust_tests_demo:starting")

TRACEPOINT_EVENT(ust_tests_demo, done,
	TP_ARGS(int, value),
	TP_FIELDS(
		ctf_integer(int, value, value)
	)
)
TRACEPOINT_LOGLEVEL(ust_tests_demo, done, TRACE_CRIT)

TRACEPOINT_MODEL_EMF_URI(ust_tests_demo, done,
	"http://example.com/path_to_model?q=ust_tests_demo:done")

#endif /* _TRACEPOINT_UST_TESTS_DEMO_H */

#undef TRACEPOINT_INCLUDE_FILE
#define TRACEPOINT_INCLUDE_FILE ./ust_tests_demo.h

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
