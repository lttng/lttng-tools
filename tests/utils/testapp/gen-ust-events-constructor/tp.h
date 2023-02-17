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

#include <stdint.h>

TRACEPOINT_EVENT(tp, main, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, constructor_c_across_units_before_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, destructor_c_across_units_before_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, constructor_c_across_units_after_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, destructor_c_across_units_after_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, constructor_c_across_units_after_provider, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, destructor_c_across_units_after_provider, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, constructor_c_same_unit_before_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, destructor_c_same_unit_before_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, constructor_c_same_unit_after_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, destructor_c_same_unit_after_define, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, constructor_c_same_unit_before_provider, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, destructor_c_same_unit_before_provider, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, constructor_c_same_unit_after_provider, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp, destructor_c_same_unit_after_provider, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp,
		 constructor_cplusplus,
		 TP_ARGS(const char *, msg),
		 TP_FIELDS(ctf_string(msg, msg)))

TRACEPOINT_EVENT(tp,
		 destructor_cplusplus,
		 TP_ARGS(const char *, msg),
		 TP_FIELDS(ctf_string(msg, msg)))

#endif /* _TRACEPOINT_TP_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
