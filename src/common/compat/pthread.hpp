/*
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _COMPAT_PTHREAD_H
#define _COMPAT_PTHREAD_H

#include <common/compat/errno.hpp>

#include <pthread.h>
#include <string.h>

#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

#define LTTNG_PTHREAD_NAMELEN 16

#if defined(HAVE_PTHREAD_SETNAME_NP_WITH_TID)
static inline int lttng_pthread_setname_np(const char *name)
{
	/*
	 * Some implementations don't error out, replicate this behavior for
	 * consistency.
	 */
	if (strnlen(name, LTTNG_PTHREAD_NAMELEN) >= LTTNG_PTHREAD_NAMELEN) {
		return ERANGE;
	}

	return pthread_setname_np(pthread_self(), name);
}
#elif defined(HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID)
static inline int lttng_pthread_setname_np(const char *name)
{
	return pthread_setname_np(name);
}
#elif defined(HAVE_PTHREAD_SET_NAME_NP_WITH_TID)

static inline int lttng_pthread_setname_np(const char *name)
{
	/* Replicate pthread_setname_np's behavior. */
	if (strnlen(name, LTTNG_PTHREAD_NAMELEN) >= LTTNG_PTHREAD_NAMELEN) {
		return ERANGE;
	}

	pthread_set_name_np(pthread_self(), name);
	return 0;
}
#elif defined(__linux__)

/* Fallback on prtctl on Linux */
#include <sys/prctl.h>

static inline int lttng_pthread_setname_np(const char *name)
{
	/* Replicate pthread_setname_np's behavior. */
	if (strnlen(name, LTTNG_PTHREAD_NAMELEN) >= LTTNG_PTHREAD_NAMELEN) {
		return ERANGE;
	}
	return prctl(PR_SET_NAME, name, 0, 0, 0);
}
#else
/*
 * For platforms without thread name support, do nothing.
 */
static inline int lttng_pthread_setname_np(const char *name)
{
	return -ENOSYS;
}
#endif

#if defined(HAVE_PTHREAD_GETNAME_NP_WITH_TID)
static inline int lttng_pthread_getname_np(char *name, size_t len)
{
	return pthread_getname_np(pthread_self(), name, len);
}
#elif defined(HAVE_PTHREAD_GETNAME_NP_WITHOUT_TID)
static inline int lttng_pthread_getname_np(char *name, size_t len)
{
	return pthread_getname_np(name, len);
}
#elif defined(HAVE_PTHREAD_GET_NAME_NP_WITH_TID)
static inline int lttng_pthread_getname_np(char *name, size_t len)
{
	pthread_get_name_np(pthread_self(), name, len);
	return 0;
}
#elif defined(__linux__)

/* Fallback on prtctl on Linux */
#include <sys/prctl.h>

static inline int lttng_pthread_getname_np(char *name, size_t len)
{
	return prctl(PR_GET_NAME, name, 0, 0, 0);
}
#else
/*
 * For platforms without thread name support, do nothing.
 */
static inline int lttng_pthread_getname_np(char *name, size_t len)
{
	return -ENOSYS;
}
#endif

#endif /* _COMPAT_PTHREAD_H */
