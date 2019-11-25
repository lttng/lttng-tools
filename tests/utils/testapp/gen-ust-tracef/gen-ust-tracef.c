/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <lttng/tracef.h>
#include "signal-helper.h"

const char *str = "test string";

static
void create_file(const char *path)
{
	int ret;

	assert(path);

	ret = creat(path, S_IRWXU);
	if (ret < 0) {
		fprintf(stderr, "Failed to create file %s\n", path);
		return;
	}

	(void) close(ret);
}

int main(int argc, char **argv)
{
	int i;
	unsigned int nr_iter = 100;
	useconds_t nr_usec = 0;
	char *tmp_file_path = NULL;

	if (set_signal_handler()) {
		return 1;
	}

	if (argc >= 2) {
		nr_iter = atoi(argv[1]);
	}

	if (argc >= 3) {
		/* By default, don't wait unless user specifies. */
		nr_usec = atoi(argv[2]);
	}

	if (argc >= 4) {
		tmp_file_path = argv[3];
	}

	for (i = 0; i < nr_iter; i++) {
		tracef("Test message %d with string \"%s\"", i, str);

		/*
		 * First loop we create the file if asked to indicate
		 * that at least one tracepoint has been hit.
		 */
		if (i == 0 && tmp_file_path) {
			create_file(tmp_file_path);
		}
		usleep(nr_usec);
		if (should_quit) {
			break;
		}
	}

	return 0;
}
