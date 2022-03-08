/*
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <urcu/uatomic.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include "fd-limit.h"
#include <common/error.h>
#include <common/compat/errno.h>

/* total count of fd. */
static long fd_count;

/*
 * threshold in % of number of fd allowed.
 */
static long fd_threshold[LTTNG_FD_NR_TYPES] = {
	75, /* LTTNG_FD_APPS */
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

void lttng_fd_put(enum lttng_fd_type type __attribute__((unused)),
		unsigned int nr)
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
