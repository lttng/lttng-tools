/*
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp

#if !defined(_TRACEPOINT_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_H

#include <lttng/tracepoint.h>

#include <sys/types.h>

TRACEPOINT_EVENT(tp, tptest, TP_ARGS(ino_t, ns_ino), TP_FIELDS(ctf_integer(ino_t, ns_ino, ns_ino)))

#endif /* _TRACEPOINT_TP_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
