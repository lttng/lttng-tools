/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdbool.h>

#ifndef LTTNG_SESSIOND_AGENT_THREAD_H
#define LTTNG_SESSIOND_AGENT_THREAD_H

#ifdef HAVE_LIBLTTNG_UST_CTL

bool launch_agent_management_thread(void);
bool agent_tracing_is_enabled(void);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline bool launch_agent_management_thread(void)
{
	return true;
}

static inline bool agent_tracing_is_enabled(void)
{
	return false;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_AGENT_THREAD_H */
