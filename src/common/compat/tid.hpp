/*
 * SPDX-FileCopyrightText: 2012 (C) Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef LTTNG_TID_H
#define LTTNG_TID_H

#ifdef __linux__
#include <syscall.h>
#endif

#if defined(__NR_gettid)

#include <unistd.h>
static inline pid_t lttng_gettid()
{
	return syscall(__NR_gettid);
}

#else

#include <sys/types.h>
#include <unistd.h>

/* Fall-back on getpid for tid if not available. */
static inline pid_t lttng_gettid(void)
{
	return getpid();
}

#endif

#endif /* LTTNG_TID_H */
