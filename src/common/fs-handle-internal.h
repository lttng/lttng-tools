/*
 * Copyright (C) 2020 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef FS_HANDLE_INTERNAL_H
#define FS_HANDLE_INTERNAL_H

struct fs_handle;

/*
 * Multiple internal APIs return fs_handles. For the moment, this internal
 * interface allows the use of different fs_handle implementations in different
 * daemons. For instance, the trace chunk interface returns fs_handles that
 * behave diffently depending on whether or not the trace chunk was configured
 * to use an fd-tracker.
 */

typedef int (*fs_handle_get_fd_cb)(struct fs_handle *);
typedef void (*fs_handle_put_fd_cb)(struct fs_handle *);
typedef int (*fs_handle_unlink_cb)(struct fs_handle *);
typedef int (*fs_handle_close_cb)(struct fs_handle *);

struct fs_handle {
	fs_handle_get_fd_cb get_fd;
	fs_handle_put_fd_cb put_fd;
	fs_handle_unlink_cb unlink;
	fs_handle_close_cb close;
};

#endif /* FS_HANDLE_INTERNAL_H */
