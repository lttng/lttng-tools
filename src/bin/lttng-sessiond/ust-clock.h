/*
 * Copyright (C) 2010  Pierre-Marc Fournier
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _UST_CLOCK_H
#define _UST_CLOCK_H

#include <common/compat/time.h>
#include <sys/time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <urcu/system.h>
#include <urcu/arch.h>
#include <lttng/ust-clock.h>

#include <common/compat/uuid.h>

/* TRACE CLOCK */

struct lttng_trace_clock {
	uint64_t (*read64)(void);
	uint64_t (*freq)(void);
	int (*uuid)(char *uuid);
	const char *(*name)(void);
	const char *(*description)(void);
};

extern struct lttng_trace_clock *lttng_trace_clock;

void lttng_ust_clock_init(void);

/*
 * Currently using the kernel MONOTONIC clock, waiting for kernel-side
 * LTTng to implement mmap'd trace clock.
 */

/* Choosing correct trace clock */

static __inline__
uint64_t trace_clock_read64_monotonic(void)
{
	struct timespec ts;

	if (lttng_clock_gettime(CLOCK_MONOTONIC, &ts)) {
		/* TODO Report error cleanly up the chain. */
		PERROR("clock_gettime CLOCK_MONOTONIC");
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	}
	return ((uint64_t) ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
}

static __inline__
uint64_t trace_clock_freq_monotonic(void)
{
	return 1000000000ULL;
}

static __inline__
int trace_clock_uuid_monotonic(char *uuid)
{
	int ret = 0;
	size_t len;
	FILE *fp;

	/*
	 * boot_id needs to be read once before being used concurrently
	 * to deal with a Linux kernel race. A fix is proposed for
	 * upstream, but the work-around is needed for older kernels.
	 */
	fp = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (!fp) {
		return -ENOENT;
	}
	len = fread(uuid, 1, LTTNG_UST_UUID_STR_LEN - 1, fp);
	if (len < LTTNG_UST_UUID_STR_LEN - 1) {
		ret = -EINVAL;
		goto end;
	}
	uuid[LTTNG_UST_UUID_STR_LEN - 1] = '\0';
end:
	fclose(fp);
	return ret;
}

static __inline__
const char *trace_clock_name_monotonic(void)
{
	return "monotonic";
}

static __inline__
const char *trace_clock_description_monotonic(void)
{
	return "Monotonic Clock";
}

static __inline__
uint64_t trace_clock_read64(void)
{
	struct lttng_trace_clock *ltc = CMM_LOAD_SHARED(lttng_trace_clock);

	if (caa_likely(!ltc)) {
		return trace_clock_read64_monotonic();
	} else {
		cmm_read_barrier_depends();	/* load ltc before content */
		return ltc->read64();
	}
}

static __inline__
uint64_t trace_clock_freq(void)
{
	struct lttng_trace_clock *ltc = CMM_LOAD_SHARED(lttng_trace_clock);

	if (!ltc) {
		return trace_clock_freq_monotonic();
	} else {
		cmm_read_barrier_depends();	/* load ltc before content */
		return ltc->freq();
	}
}

static __inline__
int trace_clock_uuid(char *uuid)
{
	struct lttng_trace_clock *ltc = CMM_LOAD_SHARED(lttng_trace_clock);

	cmm_read_barrier_depends();	/* load ltc before content */
	/* Use default UUID cb when NULL */
	if (!ltc || !ltc->uuid) {
		return trace_clock_uuid_monotonic(uuid);
	} else {
		return ltc->uuid(uuid);
	}
}

static __inline__
const char *trace_clock_name(void)
{
	struct lttng_trace_clock *ltc = CMM_LOAD_SHARED(lttng_trace_clock);

	if (!ltc) {
		return trace_clock_name_monotonic();
	} else {
		cmm_read_barrier_depends();	/* load ltc before content */
		return ltc->name();
	}
}

static __inline__
const char *trace_clock_description(void)
{
	struct lttng_trace_clock *ltc = CMM_LOAD_SHARED(lttng_trace_clock);

	if (!ltc) {
		return trace_clock_description_monotonic();
	} else {
		cmm_read_barrier_depends();	/* load ltc before content */
		return ltc->description();
	}
}

#endif /* _UST_CLOCK_H */
