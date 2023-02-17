/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp_a

#if !defined(_TRACEPOINT_TP_A_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_A_H

#include <lttng/tracepoint.h>

#include <stdint.h>

TRACEPOINT_EVENT(tp_a, constructor_c_provider_static_archive, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp_a, destructor_c_provider_static_archive, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp_a,
		 constructor_cplusplus_provider_static_archive,
		 TP_ARGS(const char *, msg),
		 TP_FIELDS(ctf_string(msg, msg)))

TRACEPOINT_EVENT(tp_a,
		 destructor_cplusplus_provider_static_archive,
		 TP_ARGS(const char *, msg),
		 TP_FIELDS(ctf_string(msg, msg)))

#endif /* _TRACEPOINT_TP_A_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp-a.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
