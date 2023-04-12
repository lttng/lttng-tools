/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_gen_nevents

#if !defined(_TRACEPOINT_UST_GEN_NEVENTS_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_GEN_NEVENTS_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(ust_gen_nevents,
		 tptest0,
		 TP_ARGS(int, anint, long, value),
		 TP_FIELDS(ctf_integer(int, intfield, anint) ctf_integer(long, longfield, value)))

TRACEPOINT_EVENT(ust_gen_nevents,
		 tptest1,
		 TP_ARGS(int, anint, long, value),
		 TP_FIELDS(ctf_integer(int, intfield, anint) ctf_integer(long, longfield, value)))

TRACEPOINT_EVENT(ust_gen_nevents,
		 tptest2,
		 TP_ARGS(int, anint, long, value),
		 TP_FIELDS(ctf_integer(int, intfield, anint) ctf_integer(long, longfield, value)))

TRACEPOINT_EVENT(ust_gen_nevents,
		 tptest3,
		 TP_ARGS(int, anint, long, value),
		 TP_FIELDS(ctf_integer(int, intfield, anint) ctf_integer(long, longfield, value)))

#endif /* _TRACEPOINT_UST_GEN_NEVENTS_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_gen_nevents.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
