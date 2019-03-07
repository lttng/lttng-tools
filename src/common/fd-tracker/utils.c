/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/fd-tracker/utils.h>
#include <common/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int open_pipe_cloexec(void *data, int *fds)
{
	return utils_create_pipe_cloexec(fds);
}

static int close_pipe(void *data, int *pipe)
{
	utils_close_pipe(pipe);
	pipe[0] = pipe[1] = -1;
	return 0;
}

int fd_tracker_util_close_fd(void *unused, int *fd)
{
	return close(*fd);
}

int fd_tracker_util_pipe_open_cloexec(
		struct fd_tracker *tracker, const char *name, int *pipe)
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
	return fd_tracker_close_unsuspendable_fd(
			tracker, pipe, 2, close_pipe, NULL);
}
