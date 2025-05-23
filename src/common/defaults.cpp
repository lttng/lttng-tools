/*
 * SPDX-FileCopyrightText: 2012 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "defaults.hpp"
#include "error.hpp"
#include "macros.hpp"

#include <algorithm>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/resource.h>
#include <unistd.h>

static int pthread_attr_init_done;
static pthread_attr_t tattr;

static size_t get_page_size()
{
	const long ret = sysconf(_SC_PAGE_SIZE);

	if (ret < 0) {
		/*
		 * Fatal error since there is no safe way to recover from this.
		 */
		PERROR("Failed to get system page size using sysconf(_SC_PAGE_SIZE)");
		abort();
	}

	return (size_t) ret;
}

size_t default_get_channel_subbuf_size()
{
	return std::max<size_t>(_DEFAULT_CHANNEL_SUBBUF_SIZE, get_page_size());
}

size_t default_get_metadata_subbuf_size()
{
	return std::max<size_t>(DEFAULT_METADATA_SUBBUF_SIZE, get_page_size());
}

size_t default_get_kernel_channel_subbuf_size()
{
	return std::max<size_t>(DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE, get_page_size());
}

size_t default_get_ust_pid_channel_subbuf_size()
{
	return std::max<size_t>(DEFAULT_UST_PID_CHANNEL_SUBBUF_SIZE, get_page_size());
}

size_t default_get_ust_uid_channel_subbuf_size()
{
	return std::max<size_t>(DEFAULT_UST_UID_CHANNEL_SUBBUF_SIZE, get_page_size());
}

pthread_attr_t *default_pthread_attr()
{
	if (pthread_attr_init_done) {
		return &tattr;
	}

	WARN("Uninitialized pthread attributes, using libc defaults.");
	return nullptr;
}

static void __attribute__((constructor)) init_default_pthread_attr()
{
	int ret;
	struct rlimit rlim;
	size_t pthread_ss, system_ss, selected_ss;

	ret = pthread_attr_init(&tattr);
	if (ret) {
		errno = ret;
		PERROR("pthread_attr_init");
		goto error;
	}

	/* Get system stack size limits. */
	ret = getrlimit(RLIMIT_STACK, &rlim);
	if (ret < 0) {
		PERROR("getrlimit");
		goto error_destroy;
	}
	DBG("Stack size limits: soft %lld, hard %lld bytes",
	    (long long) rlim.rlim_cur,
	    (long long) rlim.rlim_max);

	/*
	 * getrlimit() may return a stack size of "-1", meaning "unlimited".
	 * In this case, we impose a known-good default minimum value which will
	 * override the libc's default stack size if it is smaller.
	 */
	system_ss = rlim.rlim_cur != -1 ? rlim.rlim_cur : DEFAULT_LTTNG_THREAD_STACK_SIZE;

	/* Get pthread default thread stack size. */
	ret = pthread_attr_getstacksize(&tattr, &pthread_ss);
	if (ret < 0) {
		PERROR("pthread_attr_getstacksize");
		goto error_destroy;
	}
	DBG("Default pthread stack size is %zu bytes", pthread_ss);

	selected_ss = std::max(pthread_ss, system_ss);
	if (selected_ss < DEFAULT_LTTNG_THREAD_STACK_SIZE) {
		DBG("Default stack size is too small, setting it to %zu bytes",
		    (size_t) DEFAULT_LTTNG_THREAD_STACK_SIZE);
		selected_ss = DEFAULT_LTTNG_THREAD_STACK_SIZE;
	}

	if (rlim.rlim_max > 0 && selected_ss > rlim.rlim_max) {
		WARN("Your system's stack size restrictions (%zu bytes) may be too low for the LTTng daemons to function properly, please set the stack size limit to at least %zu bytes to ensure reliable operation",
		     (size_t) rlim.rlim_max,
		     (size_t) DEFAULT_LTTNG_THREAD_STACK_SIZE);
		selected_ss = (size_t) rlim.rlim_max;
	}

	ret = pthread_attr_setstacksize(&tattr, selected_ss);
	if (ret < 0) {
		PERROR("pthread_attr_setstacksize");
		goto error_destroy;
	}
	pthread_attr_init_done = 1;
error:
	return;
error_destroy:
	ret = pthread_attr_destroy(&tattr);
	if (ret) {
		errno = ret;
		PERROR("pthread_attr_destroy");
	}
}

static void __attribute__((destructor)) fini_default_pthread_attr()
{
	int ret;

	if (!pthread_attr_init_done) {
		return;
	}

	ret = pthread_attr_destroy(&tattr);
	if (ret) {
		errno = ret;
		PERROR("pthread_attr_destroy");
	}
}
