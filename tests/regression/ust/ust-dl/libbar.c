/*
 * SPDX-FileCopyrightText: 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "libbar.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "libbar-tp.h"

int bar(void)
{
	tracepoint(libbar, bar);
	return 1;
}
