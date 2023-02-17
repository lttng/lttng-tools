/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp_so

#if !defined(_TRACEPOINT_TP_SO_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_SO_H

#include <lttng/tracepoint.h>

#include <stdint.h>

TRACEPOINT_EVENT(tp_so, constructor_c_provider_shared_library, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp_so, destructor_c_provider_shared_library, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp_so,
		 constructor_cplusplus_provider_shared_library,
		 TP_ARGS(const char *, msg),
		 TP_FIELDS(ctf_string(msg, msg)))

TRACEPOINT_EVENT(tp_so,
		 destructor_cplusplus_provider_shared_library,
		 TP_ARGS(const char *, msg),
		 TP_FIELDS(ctf_string(msg, msg)))

#endif /* _TRACEPOINT_TP_SO_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp-so.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
