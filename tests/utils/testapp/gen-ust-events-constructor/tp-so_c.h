/*
 * Copyright (C) 2024 Kienan Stewart <kstewart@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifdef _cplusplus
extern "C" {
#endif

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER tp_so_c

#if !defined(_TRACEPOINT_TP_SO_C_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_TP_SO_C_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(tp_so_c, constructor_c_provider_shared_library, TP_ARGS(), TP_FIELDS())

TRACEPOINT_EVENT(tp_so_c, destructor_c_provider_shared_library, TP_ARGS(), TP_FIELDS())

#endif /* _TRACEPOINT_TP_SO_C_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./tp-so_c.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef _cplusplus
}
#endif
