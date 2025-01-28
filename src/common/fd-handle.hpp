/*
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef FD_HANDLE_H
#define FD_HANDLE_H

#include <common/macros.hpp>

/*
 * Wrapper around a file descriptor providing reference counting semantics.
 *
 * An fd_handle will close() the underlying file descriptor when its reference
 * count reaches zero.
 */
struct fd_handle;

/* Create a file descriptor handle. */
struct fd_handle *fd_handle_create(int fd);

/* Acquire reference to a file descriptor handle. */
void fd_handle_get(struct fd_handle *handle);

/* Release reference to a file descriptor handle. */
void fd_handle_put(struct fd_handle *handle);

/*
 * Return the underlying file descriptor of a file descriptor handle.
 *
 * This function can't fail.
 */
int fd_handle_get_fd(struct fd_handle *handle);

/*
 * Obtain a copy of a file descriptor handle.
 *
 * On success, the caller becomes the sole owner of the returned file descriptor
 * handle. The underlying file descriptor is duplicated using dup(). Refer to
 * the system documentation for the semantics of dup() for this particular file
 * descriptor type.
 */
struct fd_handle *fd_handle_copy(const struct fd_handle *handle);

#endif /* FS_HANDLE_H */
