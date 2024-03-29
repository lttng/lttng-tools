/*
 * default_pipe_size_getter.c
 *
 * Tests suite for LTTng notification API (get default size of pipes)
 *
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <common/error.hpp>
#include <common/pipe.hpp>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int lttng_opt_verbose;
int lttng_opt_mi;
int lttng_opt_quiet;

namespace {
#ifdef __linux__
/*
 * Return the default pipe buffer size or a negative error.
 */
int get_pipe_size()
{
	int ret;
	/*
	 * The event notifier pipes are not "special"; they are created using
	 * the lttng_pipe utility. Hence, this should be representative of a
	 * pipe created by the session daemon for event notifier messages to
	 * go through.
	 */
	struct lttng_pipe *pipe = lttng_pipe_open(0);

	if (!pipe) {
		/* lttng_pipe_open already logs on error. */
		ret = -1;
		goto end;
	}

	ret = fcntl(lttng_pipe_get_writefd(pipe), F_GETPIPE_SZ);
	if (ret < 0) {
		PERROR("Failed to get the size of the pipe");
	}

	lttng_pipe_destroy(pipe);
end:
	return ret;
}
#elif defined(__FreeBSD__)
int get_pipe_size(void)
{
	return 65536;
}
#else
#error "Implement get_pipe_size() for your platform."
#endif
} /* namespace */

int main()
{
	int ret;

	ret = get_pipe_size();
	if (ret < 0) {
		return EXIT_FAILURE;
	}

	/* Print the pipe buffer size to stdout. */
	printf("%d\n", ret);

	return EXIT_SUCCESS;
}
