/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdbool.h>

#ifndef LTTNG_SESSIOND_AGENT_THREAD_H
#define LTTNG_SESSIOND_AGENT_THREAD_H

#ifdef HAVE_LIBLTTNG_UST_CTL

bool launch_agent_management_thread(void);
bool agent_tracing_is_enabled(void);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline
bool launch_agent_management_thread(void)
{
	return true;
}

static inline
bool agent_tracing_is_enabled(void)
{
	return false;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_AGENT_THREAD_H */
