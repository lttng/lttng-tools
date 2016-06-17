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

#define _LGPL_SOURCE
#include <stdlib.h>
#include <unistd.h>

#include <common/error.h>

#include "utils.h"
#include "lttng-sessiond.h"

int ht_cleanup_pipe[2] = { -1, -1 };

/*
 * Write to writable pipe used to notify a thread.
 */
int notify_thread_pipe(int wpipe)
{
	ssize_t ret;

	/* Ignore if the pipe is invalid. */
	if (wpipe < 0) {
		return 0;
	}

	ret = lttng_write(wpipe, "!", 1);
	if (ret < 1) {
		PERROR("write poll pipe");
	}

	return (int) ret;
}

void ht_cleanup_push(struct lttng_ht *ht)
{
	ssize_t ret;
	int fd = ht_cleanup_pipe[1];

	if (!ht) {
		return;
	}
	if (fd < 0)
		return;
	ret = lttng_write(fd, &ht, sizeof(ht));
	if (ret < sizeof(ht)) {
		PERROR("write ht cleanup pipe %d", fd);
		if (ret < 0) {
			ret = -errno;
		}
		goto error;
	}

	/* All good. Don't send back the write positive ret value. */
	ret = 0;
error:
	assert(!ret);
}

int loglevels_match(int a_loglevel_type, int a_loglevel_value,
	int b_loglevel_type, int b_loglevel_value, int loglevel_all_type)
{
	int match = 1;

	if (a_loglevel_type == b_loglevel_type) {
		/* Same loglevel type. */
		if (b_loglevel_type != loglevel_all_type) {
			/*
			 * Loglevel value must also match since the loglevel
			 * type is not all.
			 */
			if (a_loglevel_value != b_loglevel_value) {
				match = 0;
			}
		}
	} else {
		/* Loglevel type is different: no match. */
		match = 0;
	}

	return match;
}
