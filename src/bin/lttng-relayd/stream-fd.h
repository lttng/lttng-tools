#ifndef _STREAM_FD_H
#define _STREAM_FD_H

/*
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <stdint.h>

struct stream_fd;

struct stream_fd *stream_fd_open(const char *path);
struct stream_fd *stream_fd_create(const char *path_name, const char *file_name,
		uint64_t size, uint64_t count, const char *suffix);
int stream_fd_rotate(struct stream_fd *sf, const char *path_name,
		const char *file_name, uint64_t size,
		uint64_t count, uint64_t *new_count);
void stream_fd_get(struct stream_fd *sf);
void stream_fd_put(struct stream_fd *sf);
int stream_fd_get_fd(struct stream_fd *sf);
void stream_fd_put_fd(struct stream_fd *sf);

#endif /* _STREAM_FD_H */
