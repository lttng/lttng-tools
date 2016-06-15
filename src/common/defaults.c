/*
 * Copyright (C) 2012 - Simon Marchi <simon.marchi@polymtl.ca>
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

#define _LGPL_SOURCE
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <pthread.h>

#include "defaults.h"
#include "macros.h"
#include "align.h"
#include "error.h"

static bool pthread_attr_init_done;
static pthread_attr_t tattr;
static pthread_mutex_t tattr_lock = PTHREAD_MUTEX_INITIALIZER;

LTTNG_HIDDEN
size_t default_get_channel_subbuf_size(void)
{
	return max(_DEFAULT_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_metadata_subbuf_size(void)
{
	return max(DEFAULT_METADATA_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_kernel_channel_subbuf_size(void)
{
	return max(DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_ust_pid_channel_subbuf_size(void)
{
	return max(DEFAULT_UST_PID_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
size_t default_get_ust_uid_channel_subbuf_size(void)
{
	return max(DEFAULT_UST_UID_CHANNEL_SUBBUF_SIZE, PAGE_SIZE);
}

LTTNG_HIDDEN
pthread_attr_t *default_pthread_attr(void)
{
	int ret = 0;
	size_t ptstacksize;
	struct rlimit rlim;

	pthread_mutex_lock(&tattr_lock);

	/* Return cached value. */
	if (pthread_attr_init_done) {
		goto end;
	}

	/* Get system stack size limits. */
	ret = getrlimit(RLIMIT_STACK, &rlim);
	if (ret < 0) {
		PERROR("getrlimit");
		goto error;
	}
	DBG("Stack size limits: soft %lld, hard %lld bytes",
			(long long) rlim.rlim_cur,
			(long long) rlim.rlim_max);

	/* Get pthread default thread stack size. */
	ret = pthread_attr_getstacksize(&tattr, &ptstacksize);
	if (ret < 0) {
		PERROR("pthread_attr_getstacksize");
		goto error;
	}
	DBG("Default pthread stack size is %zu bytes", ptstacksize);

	/* Check if the default pthread stack size honors ulimits. */
	if (ptstacksize < rlim.rlim_cur) {
		DBG("Your libc doesn't honor stack size limits, setting thread stack size to soft limit (%lld bytes)",
				(long long) rlim.rlim_cur);

		/* Create pthread_attr_t struct with ulimit stack size. */
		ret = pthread_attr_setstacksize(&tattr, rlim.rlim_cur);
		if (ret < 0) {
			PERROR("pthread_attr_setstacksize");
			goto error;
		}
	}

	/* Enable cached value. */
	pthread_attr_init_done = true;
end:
	pthread_mutex_unlock(&tattr_lock);
	return &tattr;
error:
	pthread_mutex_unlock(&tattr_lock);
	WARN("Failed to initialize pthread attributes, using libc defaults.");
	return NULL;
}
