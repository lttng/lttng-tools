/*
 * Copyright (C) 2015 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _COMPAT_DIRENT_H
#define _COMPAT_DIRENT_H

#include <dirent.h>

#ifdef HAVE_DIRFD
static inline int lttng_dirfd(DIR *dir)
{
	return dirfd(dir);
}
#else
#ifndef __XOPEN_OR_POSIX
static inline int lttng_dirfd(DIR *dir)
{
	return dir->dd_fd;
}
#else
static inline int lttng_dirfd(DIR *dir)
{
	return dir->d_fd;
}
#endif
#endif

#endif /* _COMPAT_DIRENT_H */
