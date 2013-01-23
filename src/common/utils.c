/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <common/common.h>

#include "utils.h"

/*
 * Return the realpath(3) of the path even if the last directory token does not
 * exist. For example, with /tmp/test1/test2, if test2/ does not exist but the
 * /tmp/test1 does, the real path is returned. In normal time, realpath(3)
 * fails if the end point directory does not exist.
 */
__attribute__((visibility("hidden")))
char *utils_expand_path(const char *path)
{
	const char *end_path = path;
	char *next, *cut_path = NULL, *expanded_path = NULL;

	/* Safety net */
	if (path == NULL) {
		goto error;
	}

	/* Find last token delimited by '/' */
	while ((next = strpbrk(end_path + 1, "/"))) {
		end_path = next;
	}

	/* Cut last token from original path */
	cut_path = strndup(path, end_path - path);

	expanded_path = zmalloc(PATH_MAX);
	if (expanded_path == NULL) {
		PERROR("zmalloc expand path");
		goto error;
	}

	expanded_path = realpath((char *)cut_path, expanded_path);
	if (expanded_path == NULL) {
		switch (errno) {
		case ENOENT:
			ERR("%s: No such file or directory", cut_path);
			break;
		default:
			PERROR("realpath utils expand path");
			break;
		}
		goto error;
	}

	/* Add end part to expanded path */
	strncat(expanded_path, end_path, PATH_MAX - strlen(expanded_path) - 1);

	free(cut_path);
	return expanded_path;

error:
	free(expanded_path);
	free(cut_path);
	return NULL;
}

/*
 * Create a pipe in dst.
 */
__attribute__((visibility("hidden")))
int utils_create_pipe(int *dst)
{
	int ret;

	if (dst == NULL) {
		return -1;
	}

	ret = pipe(dst);
	if (ret < 0) {
		PERROR("create pipe");
	}

	return ret;
}

/*
 * Create pipe and set CLOEXEC flag to both fd.
 *
 * Make sure the pipe opened by this function are closed at some point. Use
 * utils_close_pipe().
 */
__attribute__((visibility("hidden")))
int utils_create_pipe_cloexec(int *dst)
{
	int ret, i;

	if (dst == NULL) {
		return -1;
	}

	ret = utils_create_pipe(dst);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = fcntl(dst[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl pipe cloexec");
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Close both read and write side of the pipe.
 */
__attribute__((visibility("hidden")))
void utils_close_pipe(int *src)
{
	int i, ret;

	if (src == NULL) {
		return;
	}

	for (i = 0; i < 2; i++) {
		/* Safety check */
		if (src[i] < 0) {
			continue;
		}

		ret = close(src[i]);
		if (ret) {
			PERROR("close pipe");
		}
	}
}

/*
 * Create a new string using two strings range.
 */
__attribute__((visibility("hidden")))
char *utils_strdupdelim(const char *begin, const char *end)
{
	char *str;

	str = zmalloc(end - begin + 1);
	if (str == NULL) {
		PERROR("zmalloc strdupdelim");
		goto error;
	}

	memcpy(str, begin, end - begin);
	str[end - begin] = '\0';

error:
	return str;
}

/*
 * Set CLOEXEC flag to the give file descriptor.
 */
__attribute__((visibility("hidden")))
int utils_set_fd_cloexec(int fd)
{
	int ret;

	if (fd < 0) {
		ret = -EINVAL;
		goto end;
	}

	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl cloexec");
		ret = -errno;
	}

end:
	return ret;
}

/*
 * Create pid file to the given path and filename.
 */
__attribute__((visibility("hidden")))
int utils_create_pid_file(pid_t pid, const char *filepath)
{
	int ret;
	FILE *fp;

	assert(filepath);

	fp = fopen(filepath, "w");
	if (fp == NULL) {
		PERROR("open pid file %s", filepath);
		ret = -1;
		goto error;
	}

	ret = fprintf(fp, "%d\n", pid);
	if (ret < 0) {
		PERROR("fprintf pid file");
	}

	fclose(fp);
	DBG("Pid %d written in file %s", pid, filepath);
error:
	return ret;
}

/*
 * Recursively create directory using the given path and mode.
 *
 * On success, return 0 else a negative error code.
 */
__attribute__((visibility("hidden")))
int utils_mkdir_recursive(const char *path, mode_t mode)
{
	char *p, tmp[PATH_MAX];
	struct stat statbuf;
	size_t len;
	int ret;

	assert(path);

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
			if (tmp[strlen(tmp) - 1] == '.' &&
					tmp[strlen(tmp) - 2] == '.' &&
					tmp[strlen(tmp) - 3] == '/') {
				ERR("Using '/../' is not permitted in the trace path (%s)",
						tmp);
				ret = -1;
				goto error;
			}
			ret = stat(tmp, &statbuf);
			if (ret < 0) {
				ret = mkdir(tmp, mode);
				if (ret < 0) {
					if (errno != EEXIST) {
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
		if (errno != EEXIST) {
			PERROR("mkdir recursive last piece");
			ret = -errno;
		} else {
			ret = 0;
		}
	}

error:
	return ret;
}
