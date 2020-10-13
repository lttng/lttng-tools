/*
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _COMPAT_PTHREAD_H
#define _COMPAT_PTHREAD_H

#include <pthread.h>
#include <common/compat/errno.h>

#if defined(HAVE_PTHREAD_SETNAME_NP_WITH_TID)
static inline
int lttng_pthread_setname_np(const char *name)
{
	return pthread_setname_np(pthread_self(), name);
}
#elif defined(HAVE_PTHREAD_SETNAME_NP_WITHOUT_TID)
static inline
int lttng_pthread_setname_np(const char *name)
{
	return pthread_setname_np(name);
}
#else
/*
 * For platforms without thread name support, do nothing.
 */
static inline
int lttng_pthread_setname_np(const char *name)
{
	return -ENOSYS;
}
#endif

#endif /* _COMPAT_PTHREAD_H */
