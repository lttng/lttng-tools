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

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <common/pipe.h>
#include <common/error.h>

int lttng_opt_verbose;
int lttng_opt_mi;
int lttng_opt_quiet;

int main(int argc, const char **argv)
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
		ret = EXIT_FAILURE;
		goto end;
	}

	ret = fcntl(lttng_pipe_get_writefd(pipe), F_GETPIPE_SZ);
	if (ret < 0) {
		PERROR("Failed to get the size of the pipe");
		ret = EXIT_FAILURE;
		goto end;
	}

	printf("%d\n", ret);
	ret = EXIT_SUCCESS;
end:
	lttng_pipe_destroy(pipe);
	return ret;
}
