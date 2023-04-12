/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_CONSUMERD_H
#define _LTTNG_CONSUMERD_H

#include <common/consumer/consumer.hpp>

#define NR_LTTNG_CONSUMER_READY 1
extern int lttng_consumer_ready;

extern const char *tracing_group_name;

/*
 * This function is dlsym-ed from a test, so needs to be exported.  Making it
 * have a C linkage name makes it easier, as it avoids having to look up a
 * mangled name.
 */
extern "C" LTTNG_EXPORT enum lttng_consumer_type lttng_consumer_get_type();

#endif /* _LTTNG_CONSUMERD_H */
