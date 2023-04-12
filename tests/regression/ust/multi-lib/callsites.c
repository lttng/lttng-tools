/*
 * Copyright (C) - 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "callsites.h"
#include "probes.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef VALUE
#define VALUE (-1)
#endif

void call_tracepoint(void)
{
	tracepoint(multi, tp, VALUE);
}
