/*
 * Copyright (C) 2011 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <common/compat/fcntl.h>
#include <common/macros.h>
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
