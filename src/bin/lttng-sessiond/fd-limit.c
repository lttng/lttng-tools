/*
 * Copyright (C) 2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <urcu/uatomic.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdio.h>
#include "fd-limit.h"
#include <common/error.h>

/* total count of fd. */
static long fd_count;

/*
 * threshold in % of number of fd allowed.
 */
static long fd_threshold[LTTNG_FD_NR_TYPES] = {
	[LTTNG_FD_APPS] = 75,
};

static rlim_t max_nr_fd;

int lttng_fd_get(enum lttng_fd_type type, unsigned int nr)
{
	long newval;

	if (type >= LTTNG_FD_NR_TYPES) {
		return -EINVAL;
	}

	newval = uatomic_add_return(&fd_count, (long) nr);
	if ((long) (newval * 100)
			- (long) (max_nr_fd * fd_threshold[type]) > 0) {
		uatomic_sub(&fd_count, (long) nr);
		return -EPERM;
	}
	return 0;
}

void lttng_fd_put(enum lttng_fd_type type, unsigned int nr)
{
	uatomic_sub(&fd_count, (long) nr);
}

void lttng_fd_init(void)
{
	struct rlimit rlim;
	int ret;

	ret = getrlimit(RLIMIT_NOFILE, &rlim);
	if (ret < 0) {
		PERROR("getrlimit");
	}
	max_nr_fd = rlim.rlim_cur;
}
