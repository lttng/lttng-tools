/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef FS_HANDLE_H
#define FS_HANDLE_H

#include <common/macros.hpp>

#include <stdio.h>

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
int fs_handle_get_fd(struct fs_handle *handle);

/*
 * Used by the caller to signal that it is no longer using the underlying fd and
 * that it may be safely suspended.
 */
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
int fs_handle_unlink(struct fs_handle *handle);

/*
 * Frees the handle and discards the underlying fd.
 */
int fs_handle_close(struct fs_handle *handle);

ssize_t fs_handle_read(struct fs_handle *handle, void *buf, size_t count);

ssize_t fs_handle_write(struct fs_handle *handle, const void *buf, size_t count);

int fs_handle_truncate(struct fs_handle *handle, off_t offset);

off_t fs_handle_seek(struct fs_handle *handle, off_t offset, int whence);

#endif /* FS_HANDLE_H */
