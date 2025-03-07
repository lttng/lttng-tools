/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lttng_consumerd

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "lib/tpp/consumerd.hpp"

#if !defined(TPP_CONSUMERD_H_) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define TPP_CONSUMERD_H_

#include <lttng/tracepoint.h>

/*
 * Use LTTNG_UST_TRACEPOINT_EVENT(), LTTNG_UST_TRACEPOINT_EVENT_CLASS(),
 * LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(), and
 * LTTNG_UST_TRACEPOINT_LOGLEVEL() here.
 */

#endif /* TPP_CONSUMERD_H_ */

#include <lttng/tracepoint-event.h>
