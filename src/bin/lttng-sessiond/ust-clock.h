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

#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>

#include <common/compat/uuid.h>

/* TRACE CLOCK */

/*
 * Currently using the kernel MONOTONIC clock, waiting for kernel-side
 * LTTng to implement mmap'd trace clock.
 */

/* Choosing correct trace clock */

static __inline__
uint64_t trace_clock_read64(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((uint64_t) ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
}

static __inline__
uint64_t trace_clock_freq(void)
{
	return 1000000000ULL;
}

static __inline__
int trace_clock_uuid(char *uuid)
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
	len = fread(uuid, 1, UUID_STR_LEN - 1, fp);
	if (len < UUID_STR_LEN - 1) {
		ret = -EINVAL;
		goto end;
	}
	uuid[UUID_STR_LEN - 1] = '\0';
end:
	fclose(fp);
	return ret;
}

#endif /* _UST_CLOCK_H */
