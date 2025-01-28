/*
 * SPDX-FileCopyrightText: 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef COMMON_LOCKFILE_H
#define COMMON_LOCKFILE_H

/*
 * Create lock file to the given path and filename.
 * Returns the associated file descriptor, -1 on error.
 *
 * Note that on systems that don't support flock, POSIX file locks are used.
 * As such, the file lock is dropped whenever any of the file descriptors
 * associated to the file's description is closed.
 *
 * For instance, the lock file is dropped if the process forks+exits or
 * forks+execve as the child process closes a file descriptor referencing
 * the file description of 'filepath'.
 */
int utils_create_lock_file(const char *filepath);

#endif /* COMMON_LOCKFILE_H */
