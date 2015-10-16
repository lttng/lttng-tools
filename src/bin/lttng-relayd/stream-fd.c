/*
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _LGPL_SOURCE
#include <common/common.h>

#include "stream-fd.h"

struct stream_fd *stream_fd_create(int fd)
{
	struct stream_fd *sf;

	sf = zmalloc(sizeof(*sf));
	if (!sf) {
		goto end;
	}
	urcu_ref_init(&sf->ref);
	sf->fd = fd;
end:
	return sf;
}

void stream_fd_get(struct stream_fd *sf)
{
	urcu_ref_get(&sf->ref);
}

static void stream_fd_release(struct urcu_ref *ref)
{
	struct stream_fd *sf = caa_container_of(ref, struct stream_fd, ref);
	int ret;

	ret = close(sf->fd);
	if (ret) {
		PERROR("Error closing stream FD %d", sf->fd);
	}
	free(sf);
}

void stream_fd_put(struct stream_fd *sf)
{
	urcu_ref_put(&sf->ref, stream_fd_release);
}
