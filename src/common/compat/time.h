/*
 * Copyright (C) 2016 Michael Jeanson <mjeanson@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _COMPAT_TIME_H
#define _COMPAT_TIME_H

#include <time.h>

#ifdef __APPLE__

typedef uint64_t timer_t;

#include <mach/mach.h>
#include <mach/clock.h>
#include <errno.h>

#undef NSEC_PER_SEC
#undef NSEC_PER_MSEC
#undef NSEC_PER_USEC

#endif /* __APPLE__ */

/* macOS/OS X 10.12 (Sierra) and up provide clock_gettime() */
#if defined(__APPLE__) && !defined(LTTNG_HAVE_CLOCK_GETTIME)

typedef int clockid_t;
#define CLOCK_REALTIME CALENDAR_CLOCK
#define CLOCK_MONOTONIC SYSTEM_CLOCK

static inline
int lttng_clock_gettime(clockid_t clk_id, struct timespec *tp)
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

static inline
int lttng_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	return clock_gettime(clk_id, tp);
}

#endif /* __APPLE__ && !LTTNG_HAVE_CLOCK_GETTIME */

#endif /* _COMPAT_TIME_H */
