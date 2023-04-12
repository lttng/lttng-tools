/*
 * Copyright (C) 2016 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _COMPAT_TIME_H
#define _COMPAT_TIME_H

#include <time.h>

#ifdef __APPLE__

#include <cstdint>

typedef uint64_t timer_t;

#include <common/compat/errno.hpp>

#include <mach/clock.h>
#include <mach/mach.h>

#undef NSEC_PER_SEC
#undef NSEC_PER_MSEC
#undef NSEC_PER_USEC
#undef USEC_PER_SEC

#endif /* __APPLE__ */

/* macOS/OS X 10.12 (Sierra) and up provide clock_gettime() */
#if defined(__APPLE__) && !defined(LTTNG_HAVE_CLOCK_GETTIME)

typedef int clockid_t;
#define CLOCK_REALTIME	CALENDAR_CLOCK
#define CLOCK_MONOTONIC SYSTEM_CLOCK

static inline int lttng_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	int ret = 0;
	clock_serv_t clock;
	mach_timespec_t now;

	if (clk_id != CLOCK_REALTIME && clk_id != CLOCK_MONOTONIC) {
		ret = -1;
		errno = EINVAL;
		goto end;
	}

	host_get_clock_service(mach_host_self(), clk_id, &clock);

	ret = clock_get_time(clock, &now);
	if (ret != KERN_SUCCESS) {
		ret = -1;
		goto deallocate;
	}

	tp->tv_sec = now.tv_sec;
	tp->tv_nsec = now.tv_nsec;

deallocate:
	mach_port_deallocate(mach_task_self(), clock);
end:
	return ret;
}

#else /* __APPLE__ && !LTTNG_HAVE_CLOCK_GETTIME */

static inline int lttng_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	return clock_gettime(clk_id, tp);
}

#endif /* __APPLE__ && !LTTNG_HAVE_CLOCK_GETTIME */

#endif /* _COMPAT_TIME_H */
