/*
 * Copyright (C) 2016 Antoine Busque <abusque@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "libbar.h"
#include "libfoo.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "libfoo-tp.h"

int foo(void)
{
	tracepoint(libfoo, foo);
	bar();
	return 1;
}
