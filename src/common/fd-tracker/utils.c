/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <common/fd-tracker/utils.h>
#include <common/utils.h>

static
int open_pipe_cloexec(void *data, int *fds)
{
	int ret;

	ret = utils_create_pipe_cloexec(fds);
	if (ret < 0) {
		goto end;
	}
end:
	return ret;
}

static
int close_pipe(void *data, int *pipe)
{
	utils_close_pipe(pipe);
	pipe[0] = pipe[1] = -1;
	return 0;
}

int fd_tracker_util_close_fd(void *unused, int *fd)
{
	return close(*fd);
}

int fd_tracker_util_pipe_open_cloexec(struct fd_tracker *tracker,
		const char *name, int *pipe)
{
	int ret;
	const char *name_prefix;
	char *names[2];

	name_prefix = name ? name : "Unknown pipe";
	ret = asprintf(&names[0], "%s (read end)", name_prefix);
	if (ret < 0) {
		goto end;
	}
	ret = asprintf(&names[1], "%s (write end)", name_prefix);
	if (ret < 0) {
		goto end;
	}

        ret = fd_tracker_open_unsuspendable_fd(tracker, pipe,
			(const char **) names, 2, open_pipe_cloexec, NULL);
	free(names[0]);
	free(names[1]);
end:
	return ret;
}

int fd_tracker_util_pipe_close(struct fd_tracker *tracker, int *pipe)
{
        return fd_tracker_close_unsuspendable_fd(tracker,
			pipe, 2, close_pipe, NULL);
}
