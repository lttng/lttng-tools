/*
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
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

using fs_handle_get_fd_cb = int (*)(struct fs_handle *);
using fs_handle_put_fd_cb = void (*)(struct fs_handle *);
using fs_handle_unlink_cb = int (*)(struct fs_handle *);
using fs_handle_close_cb = int (*)(struct fs_handle *);

struct fs_handle {
	fs_handle_get_fd_cb get_fd;
	fs_handle_put_fd_cb put_fd;
	fs_handle_unlink_cb unlink;
	fs_handle_close_cb close;
};

#endif /* FS_HANDLE_INTERNAL_H */
