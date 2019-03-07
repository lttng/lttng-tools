/*
 * Copyright (C) 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _COMPAT_PRCTL_H
#define _COMPAT_PRCTL_H

#ifdef __linux__
#include <sys/prctl.h>

static inline
int lttng_prctl(int option, unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5)
{
	return prctl(option, arg2, arg3, arg4, arg5);
}

#else

#ifndef PR_SET_NAME
#define PR_SET_NAME 0
#endif /* PR_SET_NAME */

static inline
int lttng_prctl(int option, unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5)
{
	return -ENOSYS;
}

#endif /* __linux__ */

#endif /* _COMPAT_PRCTL_H */
