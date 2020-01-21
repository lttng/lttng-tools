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

#ifndef FS_HANDLE_H
#define FS_HANDLE_H

#include <common/macros.h>

struct fs_handle;

/*
 * Marks the handle as the most recently used and marks the 'fd' as
 * "in-use". This prevents the tracker from recycling the underlying
 * file descriptor while it is actively being used by a thread.
 *
 * Don't forget that the tracker may be initiating an fd 'suspension'
 * from another thread as the need to free an fd slot may arise from any
 * thread within the daemon.
 *
 * Note that a restorable fd should never be held for longer than
 * strictly necessary (e.g. the duration of a syscall()).
 *
 * Returns the fd on success, otherwise a negative value may be returned
 * if the restoration of the fd failed.
 */
LTTNG_HIDDEN
int fs_handle_get_fd(struct fs_handle *handle);

/*
 * Used by the caller to signal that it is no longer using the underlying fd and
 * that it may be safely suspended.
 */
LTTNG_HIDDEN
void fs_handle_put_fd(struct fs_handle *handle);

/*
 * Unlink the file associated to an fs_handle. Note that the unlink
 * operation will not be performed immediately. It will only be performed
 * once all references to the underlying file (through other fs_handle objects)
 * have been released.
 *
 * However, note that the file will be renamed so as to provide the observable
 * effect of an unlink(), that is removing a name from the filesystem.
 *
 * Returns 0 on success, otherwise a negative value will be returned
 * if the operation failed.
 */
LTTNG_HIDDEN
int fs_handle_unlink(struct fs_handle *handle);

/*
 * Frees the handle and discards the underlying fd.
 */
LTTNG_HIDDEN
int fs_handle_close(struct fs_handle *handle);

#endif /* FS_HANDLE_H */
