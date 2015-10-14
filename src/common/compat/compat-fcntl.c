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

#define _LGPL_SOURCE
#include <common/compat/fcntl.h>
#include <unistd.h>

#ifdef __linux__

int compat_sync_file_range(int fd, off64_t offset, off64_t nbytes,
		unsigned int flags)
{
#ifdef HAVE_SYNC_FILE_RANGE
	return sync_file_range(fd, offset, nbytes, flags);
#else
	return fdatasync(fd);
#endif
}

#endif /* __linux__ */
