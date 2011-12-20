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
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <lttngerr.h>

#include "utils.h"

struct mkdir_data {
	const char *path;
	mode_t mode;
};

struct open_data {
	const char *path;
	int flags;
	mode_t mode;
};

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
static
int _mkdir_recursive(void *_data)
{
	struct mkdir_data *data = _data;
	const char *path;
	char *p, tmp[PATH_MAX];
	struct stat statbuf;
	mode_t mode;
	size_t len;
	int ret;

	path = data->path;
	mode = data->mode;

	ret = snprintf(tmp, sizeof(tmp), "%s", path);
	if (ret < 0) {
		PERROR("snprintf mkdir");
		goto error;
	}

	len = ret;
	if (tmp[len - 1] == '/') {
		tmp[len - 1] = 0;
	}

	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			ret = stat(tmp, &statbuf);
			if (ret < 0) {
				ret = mkdir(tmp, mode);
				if (ret < 0) {
					if (!(errno == EEXIST)) {
						PERROR("mkdir recursive");
						ret = -errno;
						goto error;
					}
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
	}

error:
	return ret;
}

static
int _mkdir(void *_data)
{
	struct mkdir_data *data = _data;
	return mkdir(data->path, data->mode);
}

static
int _open(void *_data)
{
	struct open_data *data = _data;
	return open(data->path, data->flags, data->mode);
}

static
int run_as(int (*cmd)(void *data), void *data, uid_t uid, gid_t gid)
{
	int ret = 0;
	pid_t pid;

	/*
	 * If we are non-root, we can only deal with our own uid.
	 */
	if (geteuid() != 0) {
		if (uid != geteuid()) {
			ERR("Client (%d)/Server (%d) UID mismatch (and sessiond is not root)",
				uid, geteuid());
			return -EPERM;
		}
		return (*cmd)(data);
	}

	pid = fork();
	if (pid > 0) {
		int status;

		/*
		 * Parent: wait for child to return, in which case the
		 * shared memory map will have been created.
		 */
		pid = wait(&status);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			ret = -1;
			goto end;
		}
		goto end;
	} else if (pid == 0) {
		/* Child */
		setegid(gid);
		if (ret < 0) {
			perror("setegid");
			exit(EXIT_FAILURE);
		}
		ret = seteuid(uid);
		if (ret < 0) {
			perror("seteuid");
			exit(EXIT_FAILURE);
		}
		umask(0);
		ret = (*cmd)(data);
		if (!ret)
			exit(EXIT_SUCCESS);
		else
			exit(EXIT_FAILURE);
	} else {
		return -1;
	}
end:
	return ret;
}

int mkdir_recursive_run_as(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	struct mkdir_data data;

	DBG3("mkdir() recursive %s with mode %d for uid %d and gid %d",
			path, mode, uid, gid);
	data.path = path;
	data.mode = mode;
	return run_as(_mkdir_recursive, &data, uid, gid);
}

int mkdir_run_as(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	struct mkdir_data data;

	DBG3("mkdir() %s with mode %d for uid %d and gid %d",
			path, mode, uid, gid);
	data.path = path;
	data.mode = mode;
	return run_as(_mkdir, &data, uid, gid);
}

int open_run_as(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid)
{
	struct open_data data;

	DBG3("open() %s with flags %d mode %d for uid %d and gid %d",
			path, flags, mode, uid, gid);
	data.path = path;
	data.flags = flags;
	data.mode = mode;
	return run_as(_open, &data, uid, gid);
}
