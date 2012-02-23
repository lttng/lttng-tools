/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _COMPAT_CLONE_H
#define _COMPAT_CLONE_H

#ifdef __linux__

#include <sched.h>

static inline
int lttng_clone_files(int (*fn)(void *), void *child_stack, void *arg)
{
	return clone(fn, child_stack, CLONE_FILES | SIGCHLD, arg);
}

#elif __FreeBSD__

#include <unistd.h>

static inline
int lttng_clone_files(int (*fn)(void *), void *child_stack, void *arg)
{
	return rfork(RFPROC | RFTHREAD);
}

#else
#error "Please add support for your OS into compat/clone.h."
#endif /* __linux__ , __FreeBSD__ */

#endif /* _COMPAT_CLONE_H */
