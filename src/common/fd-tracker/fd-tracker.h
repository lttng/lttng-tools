/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef FD_TRACKER_H
#define FD_TRACKER_H

#include <stdint.h>
#include <sys/types.h>

struct fs_handle;
struct fd_tracker;

/*
 * Callback which returns a file descriptor to track through the fd
 * tracker. This callback must not make use of the fd_tracker as a deadlock
 * may occur.
 *
 * The int pointer argument is an output parameter that should be used to return
 * the advertised number of file descriptors.
 *
 * Must return zero on success. Negative values should map to a UNIX error code.
 */
typedef int (*fd_open_cb)(void *, int *out_fds);

/*
 * Callback to allow the user to close a now-untracked file descriptor. This
 * callback must not make use of the fd_tracker as a deadlock may occur.
 *
 * The callback can freely modify the in_fds argument as it is copied by the
 * fd_tracker before being used. The fd tracker assumes in_fds to be closed by
 * the time the callback returns.
 *
 * Must return zero on success. Negative values should map to a UNIX error code.
 */
typedef int (*fd_close_cb)(void *, int *in_fds);

/*
 * Set the maximal number of fds that the process should be allowed to open at
 * any given time. This function must be called before any other of this
 * interface.
 */
struct fd_tracker *fd_tracker_create(unsigned int capacity);

/* Returns an error if file descriptors are leaked. */
int fd_tracker_destroy(struct fd_tracker *tracker);

/*
 * Open a handle to a suspendable filesystem file descriptor.
 *
 * See OPEN(3) for an explanation of flags and mode. NULL is returned in case of
 * error and errno is left untouched. Note that passing NULL as mode will result
 * in open()'s default behaviour being used (using the process' umask).
 *
 * A fs_handle wraps a file descriptor created by OPEN(3). It is suspendable
 * meaning that the underlying file may be closed at any time unless the
 * handle is marked as being in-use (see fs_handle_get_fd() and
 * fs_handle_put_fd()).
 *
 * If the tracker opted to close the underlying file descriptor, it will
 * be restored to its last known state when it is obtained through
 * the fs_handle's fs_handle_get_fd() method.
 *
 * Note that a suspendable file descriptor can be closed by the fd tracker at
 * anytime when it is not in use. This means that the user should not rely on it
 * being safe to unlink the file. Moreover, concurent modifications to the file
 * (e.g. truncation) may react differently than if the file descriptor was kept
 * open.
 */
struct fs_handle *fd_tracker_open_fs_handle(struct fd_tracker *tracker,
		const char *path, int flags, mode_t *mode);

/*
 * Open a tracked unsuspendable file descriptor.
 *
 * This function allows the fd tracker to keep track of unsuspendable
 * file descriptors. A callback, open, is passed to allow the tracker
 * to atomically reserve an entry for a given count of new file descriptors,
 * suspending file descriptors as needed, and invoke the provided callback
 * without ever exceeding the tracker's capacity.
 *
 * fd_count indicates the count of file descriptors that will be opened and
 * returned by the open callback. The storage location at out_fds is assumed
 * to be large enough to hold 'fd_count * sizeof(int)'.
 *
 * Names may be provided to allow easier debugging of file descriptor
 * exhaustions.
 *
 * The callback's return value is returned to the user. Additionally, two
 * negative tracker-specific codes may be returned:
 *   - ENOMEM: allocation of a new entry failed,
 *   - EMFILE: too many unsuspendable fds are opened and the tracker can't
 *             accomodate the request for a new unsuspendable entry.
 */
int fd_tracker_open_unsuspendable_fd(struct fd_tracker *tracker,
		int *out_fds, const char **names, unsigned int fd_count,
		fd_open_cb open, void *data);

/*
 * Close a tracked unsuspendable file descriptor.
 *
 * This function allows the fd tracker to keep track of unsuspendable
 * file descriptors. A callback, close, is passed to allow the tracker
 * to atomically release a file descriptor entry.
 *
 * Returns 0 if the close callback returned success. Returns the value returned
 * by the close callback if it is negative. Additionally, a tracker-specific
 * code may be returned:
 *   - EINVAL: a file descriptor was unknown to the tracker
 *
 * Closed fds are set to -1 in the fds array which, in the event of an error,
 * allows the user to know which file descriptors are no longer being tracked.
 */
int fd_tracker_close_unsuspendable_fd(struct fd_tracker *tracker,
		int *fds, unsigned int fd_count, fd_close_cb close,
		void *data);

/*
 * Log the contents of the fd_tracker.
 */
void fd_tracker_log(struct fd_tracker *tracker);

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
 * Used by the application to signify that it is no longer using the
 * underlying fd and that it may be suspended.
 */
void fs_handle_put_fd(struct fs_handle *handle);

/*
 * Frees the handle and discards the underlying fd.
 */
int fs_handle_close(struct fs_handle *handle);

#endif /* FD_TRACKER_H */
