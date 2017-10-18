/*
 * Copyright (C) - 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdint.h>
#include <common/compat/time.h>
#include <common/time.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

static inline
int64_t elapsed_time_ns(struct timespec *t1, struct timespec *t2)
{
	struct timespec delta;

	assert(t1 && t2);
	delta.tv_sec = t2->tv_sec - t1->tv_sec;
	delta.tv_nsec = t2->tv_nsec - t1->tv_nsec;
	return ((int64_t) NSEC_PER_SEC * (int64_t) delta.tv_sec) +
			(int64_t) delta.tv_nsec;
}

int usleep_safe(useconds_t usec)
{
	int ret = 0;
	struct timespec t1, t2;
	int64_t time_remaining_ns = (int64_t) usec * (int64_t) NSEC_PER_USEC;

	ret = lttng_clock_gettime(CLOCK_MONOTONIC, &t1);
	if (ret) {
		ret = -1;
		perror("clock_gettime");
		goto end;
	}

	while (time_remaining_ns > 0) {
		ret = usleep(time_remaining_ns / (int64_t) NSEC_PER_USEC);
		if (ret && errno != EINTR) {
			perror("usleep");
			goto end;
		}

		ret = lttng_clock_gettime(CLOCK_MONOTONIC, &t2);
		if (ret) {
			perror("clock_gettime");
			goto end;
		}

		time_remaining_ns -= elapsed_time_ns(&t1, &t2);
	}
end:
	return ret;
}
