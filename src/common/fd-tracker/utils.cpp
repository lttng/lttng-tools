/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/fd-tracker/utils.hpp>
#include <common/utils.hpp>
#include <lttng/constant.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static
int open_pipe_cloexec(void *data __attribute__((unused)), int *fds)
{
	return utils_create_pipe_cloexec(fds);
}

static
int close_pipe(void *data __attribute__((unused)), int *pipe)
{
	utils_close_pipe(pipe);
	pipe[0] = pipe[1] = -1;
	return 0;
}

int fd_tracker_util_close_fd(void *unused __attribute__((unused)), int *fd)
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

namespace {
struct open_directory_handle_args {
	const struct lttng_directory_handle *in_handle;
	struct lttng_directory_handle *ret_handle;
	const char *path;
};
} /* namespace */

static
int open_directory_handle(void *_args, int *out_fds)
{
	int ret = 0;
	struct open_directory_handle_args *args = (open_directory_handle_args *) _args;
	struct lttng_directory_handle *new_handle = NULL;

	new_handle = args->in_handle ?
			lttng_directory_handle_create_from_handle(
				args->path, args->in_handle) :
			lttng_directory_handle_create(args->path);
	if (!new_handle) {
		ret = -errno;
		goto end;
	}

	args->ret_handle = new_handle;

	/*
	 * Reserved to indicate that the handle does not use a handle; there is
	 * nothing to track. We want to indicate an error to the fd-tracker so
	 * that it doesn't attempt to track the file descriptor, but also want
	 * the caller to retrieve the newly-created handle.
	 *
	 * Calling this a hack is a fair assessment.
	 */
	if (!lttng_directory_handle_uses_fd(new_handle)) {
		ret = ENOTSUP;
	} else {
#ifdef HAVE_DIRFD
		*out_fds = new_handle->dirfd;
#else
		abort();
#endif

	}
end:
	return ret;
}

#ifdef HAVE_DIRFD
static
int fd_close(void *unused __attribute__((unused)), int *in_fds)
{
	const int ret = close(in_fds[0]);

	in_fds[0] = -1;
	return ret;
}

static
void directory_handle_destroy(
		struct lttng_directory_handle *handle, void *data)
{
	struct fd_tracker *tracker = (fd_tracker *) data;
	const int ret = fd_tracker_close_unsuspendable_fd(
			tracker, &handle->dirfd, 1, fd_close, NULL);

	if (ret) {
		ERR("Failed to untrack directory handle file descriptor");
	}
}
#endif

struct lttng_directory_handle *fd_tracker_create_directory_handle(
		struct fd_tracker *tracker, const char *path)
{
	return fd_tracker_create_directory_handle_from_handle(
			tracker, NULL, path);
}

struct lttng_directory_handle *fd_tracker_create_directory_handle_from_handle(
		struct fd_tracker *tracker,
		struct lttng_directory_handle *in_handle,
		const char *path)
{
	int ret;
	int dirfd = -1;
	char *handle_name = NULL;
	char cwd_path[LTTNG_PATH_MAX] = "working directory";
	struct lttng_directory_handle *new_handle = NULL;
	open_directory_handle_args open_args {};

	open_args.in_handle = in_handle;
	open_args.path = path;

	if (!path) {
		if (!getcwd(cwd_path, sizeof(cwd_path))) {
			PERROR("Failed to get current working directory to name directory handle");
			goto end;
		}
	}

	ret = asprintf(&handle_name, "Directory handle to %s",
			path ? path : cwd_path);
	if (ret < 0) {
		PERROR("Failed to format directory handle name");
		goto end;
	}

	ret = fd_tracker_open_unsuspendable_fd(tracker, &dirfd,
			(const char **) &handle_name, 1, open_directory_handle,
			&open_args);
	if (ret && ret != ENOTSUP) {
		ERR("Failed to open directory handle to %s through the fd tracker", path ? path : cwd_path);
	}
	new_handle = open_args.ret_handle;

#ifdef HAVE_DIRFD
	new_handle->destroy_cb = directory_handle_destroy;
	new_handle->destroy_cb_data = tracker;
#endif
end:
	free(handle_name);
	return new_handle;
}
