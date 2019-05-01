/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _COMPAT_DIRECTORY_HANDLE_H
#define _COMPAT_DIRECTORY_HANDLE_H

#include <common/macros.h>
#include <common/credentials.h>

/*
 * Some platforms, such as Solaris 10, do not support directory file descriptors
 * and their associated functions (*at(...)), which are defined in POSIX.2008.
 *
 * This wrapper provides a handle that is either a copy of a directory's path
 * or a directory file descriptors, depending on the platform's capabilities.
 */
#ifdef COMPAT_DIRFD
struct lttng_directory_handle {
	int dirfd;
};
#else
struct lttng_directory_handle {
	char *base_path;
};
#endif

/*
 * Initialize a directory handle to the provided path. Passing a NULL path
 * returns a handle to the current working directory. The working directory
 * is not sampled; it will be accessed at the time of use of the functions
 * of this API.
 *
 * An initialized directory handle must be finalized using
 * lttng_directory_handle_fini().
 */
LTTNG_HIDDEN
int lttng_directory_handle_init(struct lttng_directory_handle *handle,
		const char *path);

/*
 * Initialize a new directory handle from an existing directory fd.
 *
 * The new directory handle assumes the ownership of the directory fd.
 * Note that this method should only be used in very specific cases, such as
 * re-creating a directory handle from a dirfd passed over a unix socket.
 *
 * An initialized directory handle must be finalized using
 * lttng_directory_handle_fini().
 */
LTTNG_HIDDEN
int lttng_directory_handle_init_from_dirfd(
		struct lttng_directory_handle *handle, int dirfd);

/*
 * Copy a directory handle.
 */
LTTNG_HIDDEN
int lttng_directory_handle_copy(const struct lttng_directory_handle *handle,
		struct lttng_directory_handle *new_copy);

/*
 * Move a directory handle. The original directory handle may no longer be
 * used after this call. This call cannot fail; directly assign the
 * return value to the new directory handle.
 *
 * It is safe (but unnecessary) to call lttng_directory_handle_fini on the
 * original handle.
 */
LTTNG_HIDDEN
struct lttng_directory_handle
lttng_directory_handle_move(struct lttng_directory_handle *original);

/*
 * Release the resources of a directory handle.
 */
LTTNG_HIDDEN
void lttng_directory_handle_fini(struct lttng_directory_handle *handle);

/*
 * Create a subdirectory relative to a directory handle.
 */
LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory(
		const struct lttng_directory_handle *handle,
		const char *subdirectory,
		mode_t mode);

/*
 * Create a subdirectory relative to a directory handle
 * as a given user.
 */
LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory_as_user(
		const struct lttng_directory_handle *handle,
		const char *subdirectory,
		mode_t mode, const struct lttng_credentials *creds);

/*
 * Recursively create a directory relative to a directory handle.
 */
LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory_recursive(
		const struct lttng_directory_handle *handle,
		const char *subdirectory_path,
		mode_t mode);

/*
 * Recursively create a directory relative to a directory handle
 * as a given user.
 */
LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory_recursive_as_user(
		const struct lttng_directory_handle *handle,
		const char *subdirectory_path,
		mode_t mode, const struct lttng_credentials *creds);

#endif /* _COMPAT_PATH_HANDLE_H */
