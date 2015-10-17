/*
 * Copyright (C) 2015 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
