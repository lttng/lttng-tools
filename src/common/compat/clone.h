/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
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

#ifndef _COMPAT_CLONE_H
#define _COMPAT_CLONE_H

#ifdef __linux__

#include <sched.h>

static inline
pid_t lttng_clone_files(int (*fn)(void *), void *child_stack, void *arg)
{
	return clone(fn, child_stack, CLONE_FILES | SIGCHLD, arg);
}

#elif defined(__FreeBSD__)

#include <unistd.h>

static inline
pid_t lttng_clone_files(int (*fn)(void *), void *child_stack, void *arg)
{
	pid_t pid;

	pid = rfork(RFPROC | RFTHREAD);
	if (pid == 0) {
		/* child */
		int ret;

		ret = fn(arg);
		exit(ret);
	} else if (pid > 0) {
		/* parent */
		/*
		 * Just return, the caller will wait for the child.
		 */
		return pid;
	} else {
		/* Error */
		return pid;
	}
}

#elif defined(__CYGWIN__)
#warning "Cygwin doesn't support the clone() syscall. You must set the LTTNG_DEBUG_NOCLONE=1 before starting lttng-sessiond"
#include <assert.h>

static inline
pid_t lttng_clone_files(int (*fn)(void *), void *child_stack, void *arg)
{
       assert(NULL);
       return -1;
}

#else
#error "Please add support for your OS."
#endif /* __linux__ , __FreeBSD__, __CYGWIN__ */

#endif /* _COMPAT_CLONE_H */
