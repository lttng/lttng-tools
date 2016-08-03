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

#ifndef _COMPAT_FCNTL_H
#define _COMPAT_FCNTL_H

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>

#if (defined(__FreeBSD__) || defined(__CYGWIN__))
typedef long long off64_t;
#endif

#if (defined(__FreeBSD__) || defined(__sun__))
typedef off64_t loff_t;
#endif

#ifdef __linux__
extern int compat_sync_file_range(int fd, off64_t offset, off64_t nbytes,
		unsigned int flags);
#define lttng_sync_file_range(fd, offset, nbytes, flags) \
	compat_sync_file_range(fd, offset, nbytes, flags)

#endif /* __linux__ */

#if (defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__))
/*
 * Possible flags under Linux. Simply nullify them and avoid wrapper.
 */
#define SYNC_FILE_RANGE_WAIT_AFTER    0
#define SYNC_FILE_RANGE_WAIT_BEFORE   0
#define SYNC_FILE_RANGE_WRITE         0

static inline int lttng_sync_file_range(int fd, off64_t offset,
		off64_t nbytes, unsigned int flags)
{
	return -ENOSYS;
}
#endif

#if (defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__))
/*
 * Possible flags under Linux. Simply nullify them and avoid wrappers.
 */
#define SPLICE_F_MOVE       0
#define SPLICE_F_NONBLOCK   0
#define SPLICE_F_MORE       0
#define SPLICE_F_GIFT       0

static inline ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
		size_t len, unsigned int flags)
{
	return -ENOSYS;
}
#endif

#ifdef __FreeBSD__
#define POSIX_FADV_DONTNEED 0

static inline int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	return -ENOSYS;
}
#endif

#if !(defined(__linux__) || defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__) || defined(__APPLE__))
#error "Please add support for your OS."
#endif /* __linux__ , __FreeBSD__, __CYGWIN__, __sun__, __APPLE__ */

#endif /* _COMPAT_FCNTL_H */
