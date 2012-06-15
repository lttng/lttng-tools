/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <common/error.h>

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
 * Create a pipe in dst.
 */
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
