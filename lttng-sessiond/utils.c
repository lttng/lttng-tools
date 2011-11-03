/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <lttngerr.h>

#include "utils.h"

/*
 * Write to writable pipe used to notify a thread.
 */
int notify_thread_pipe(int wpipe)
{
	int ret;

	ret = write(wpipe, "!", 1);
	if (ret < 0) {
		PERROR("write poll pipe");
	}

	return ret;
}

/*
 * Return pointer to home directory path using the env variable HOME.
 *
 * No home, NULL is returned.
 */
const char *get_home_dir(void)
{
	return ((const char *) getenv("HOME"));
}

/*
 * Create recursively directory using the FULL path.
 */
int mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	int ret;
	char *p, tmp[PATH_MAX];
	size_t len;
	mode_t old_umask;

	ret = snprintf(tmp, sizeof(tmp), "%s", path);
	if (ret < 0) {
		PERROR("snprintf mkdir");
		goto error;
	}

	len = ret;
	if (tmp[len - 1] == '/') {
		tmp[len - 1] = 0;
	}

	old_umask = umask(0);
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			ret = mkdir(tmp, mode);
			if (ret < 0) {
				if (!(errno == EEXIST)) {
					PERROR("mkdir recursive");
					ret = -errno;
					goto umask_error;
				}
			} else if (ret == 0) {
				/*
				 * We created the directory. Set its ownership to the
				 * user/group specified.
				 */
				ret = chown(tmp, uid, gid);
				if (ret < 0) {
					PERROR("chown in mkdir recursive");
					ret = -errno;
					goto umask_error;
				}
			}
			*p = '/';
		}
	}

	ret = mkdir(tmp, mode);
	if (ret < 0) {
		if (!(errno == EEXIST)) {
			PERROR("mkdir recursive last piece");
			ret = -errno;
		} else {
			ret = 0;
		}
	} else if (ret == 0) {
		/*
		 * We created the directory. Set its ownership to the user/group
		 * specified.
		 */
		ret = chown(tmp, uid, gid);
		if (ret < 0) {
			PERROR("chown in mkdir recursive");
			ret = -errno;
			goto umask_error;
		}
	}

umask_error:
	umask(old_umask);
error:
	return ret;
}
