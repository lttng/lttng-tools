/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _COMPAT_DIRECTORY_HANDLE_H
#define _COMPAT_DIRECTORY_HANDLE_H

#include <common/credentials.hpp>
#include <common/macros.hpp>

#include <sys/stat.h>
#include <urcu/ref.h>

enum lttng_directory_handle_rmdir_recursive_flags {
	LTTNG_DIRECTORY_HANDLE_FAIL_NON_EMPTY_FLAG = (1U << 0),
	LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG = (1U << 1),
};

/*
 * Some platforms, such as Solaris 10, do not support directory file descriptors
 * and their associated functions (*at(...)), which are defined in POSIX.2008.
 *
 * This wrapper provides a handle that is either a copy of a directory's path
 * or a directory file descriptors, depending on the platform's capabilities.
 */
#ifdef HAVE_DIRFD

struct lttng_directory_handle;

using lttng_directory_handle_destroy_cb = void (*)(struct lttng_directory_handle *, void *);

struct lttng_directory_handle {
	struct urcu_ref ref;
	ino_t directory_inode;
	int dirfd;
	lttng_directory_handle_destroy_cb destroy_cb;
	void *destroy_cb_data;
};

static inline int lttng_directory_handle_get_dirfd(const struct lttng_directory_handle *handle)
{
	return handle->dirfd;
}

#else
struct lttng_directory_handle {
	struct urcu_ref ref;
	char *base_path;
};
#endif

/*
 * Create a directory handle to the provided path. Passing a NULL path
 * returns a handle to the current working directory.
 *
 * The reference to the directory handle must be released using
 * lttng_directory_handle_put().
 */
struct lttng_directory_handle *lttng_directory_handle_create(const char *path);

/*
 * Create a new directory handle to a path relative to an existing handle.
 *
 * The provided path must already exist. Note that the creation of a
 * subdirectory and the creation of a handle are kept as separate operations
 * to highlight the fact that there is an inherent race between the creation of
 * a directory and the creation of a handle to it.
 *
 * Passing a NULL path effectively copies the original handle.
 *
 * The reference to the directory handle must be released using
 * lttng_directory_handle_put().
 */
struct lttng_directory_handle *
lttng_directory_handle_create_from_handle(const char *path,
					  const struct lttng_directory_handle *ref_handle);

/*
 * Create a new directory handle from an existing directory fd.
 *
 * The new directory handle assumes the ownership of the directory fd.
 * Note that this method should only be used in very specific cases, such as
 * re-creating a directory handle from a dirfd passed over a unix socket.
 *
 * The reference to the directory handle must be released using
 * lttng_directory_handle_put().
 */
struct lttng_directory_handle *lttng_directory_handle_create_from_dirfd(int dirfd);

/*
 * Copy a directory handle.
 *
 * The reference to the directory handle must be released using
 * lttng_directory_handle_put().
 */
struct lttng_directory_handle *
lttng_directory_handle_copy(const struct lttng_directory_handle *handle);

/*
 * Acquire a reference to a directory handle.
 */
bool lttng_directory_handle_get(struct lttng_directory_handle *handle);

/*
 * Release a reference to a directory handle.
 */
void lttng_directory_handle_put(struct lttng_directory_handle *handle);

/*
 * Create a subdirectory relative to a directory handle.
 */
int lttng_directory_handle_create_subdirectory(const struct lttng_directory_handle *handle,
					       const char *subdirectory,
					       mode_t mode);

/*
 * Create a subdirectory relative to a directory handle
 * as a given user.
 */
int lttng_directory_handle_create_subdirectory_as_user(const struct lttng_directory_handle *handle,
						       const char *subdirectory,
						       mode_t mode,
						       const struct lttng_credentials *creds);

/*
 * Recursively create a directory relative to a directory handle.
 */
int lttng_directory_handle_create_subdirectory_recursive(
	const struct lttng_directory_handle *handle, const char *subdirectory_path, mode_t mode);

/*
 * Recursively create a directory relative to a directory handle
 * as a given user.
 */
int lttng_directory_handle_create_subdirectory_recursive_as_user(
	const struct lttng_directory_handle *handle,
	const char *subdirectory_path,
	mode_t mode,
	const struct lttng_credentials *creds);

/*
 * Open a file descriptor to a path relative to a directory handle.
 */
int lttng_directory_handle_open_file(const struct lttng_directory_handle *handle,
				     const char *filename,
				     int flags,
				     mode_t mode);

/*
 * Open a file descriptor to a path relative to a directory handle
 * as a given user.
 */
int lttng_directory_handle_open_file_as_user(const struct lttng_directory_handle *handle,
					     const char *filename,
					     int flags,
					     mode_t mode,
					     const struct lttng_credentials *creds);

/*
 * Unlink a file to a path relative to a directory handle.
 */
int lttng_directory_handle_unlink_file(const struct lttng_directory_handle *handle,
				       const char *filename);

/*
 * Unlink a file to a path relative to a directory handle as a given user.
 */
int lttng_directory_handle_unlink_file_as_user(const struct lttng_directory_handle *handle,
					       const char *filename,
					       const struct lttng_credentials *creds);

/*
 * Rename a file from a path relative to a directory handle to a new
 * name relative to another directory handle.
 */
int lttng_directory_handle_rename(const struct lttng_directory_handle *old_handle,
				  const char *old_name,
				  const struct lttng_directory_handle *new_handle,
				  const char *new_name);

/*
 * Rename a file from a path relative to a directory handle to a new
 * name relative to another directory handle as a given user.
 */
int lttng_directory_handle_rename_as_user(const struct lttng_directory_handle *old_handle,
					  const char *old_name,
					  const struct lttng_directory_handle *new_handle,
					  const char *new_name,
					  const struct lttng_credentials *creds);

/*
 * Remove a subdirectory relative to a directory handle.
 */
int lttng_directory_handle_remove_subdirectory(const struct lttng_directory_handle *handle,
					       const char *name);

/*
 * Remove a subdirectory relative to a directory handle as a given user.
 */
int lttng_directory_handle_remove_subdirectory_as_user(const struct lttng_directory_handle *handle,
						       const char *name,
						       const struct lttng_credentials *creds);

/*
 * Remove a subdirectory and remove its contents if it only
 * consists in empty directories.
 * @flags: enum lttng_directory_handle_rmdir_recursive_flags
 */
int lttng_directory_handle_remove_subdirectory_recursive(
	const struct lttng_directory_handle *handle, const char *name, int flags);

/*
 * Remove a subdirectory and remove its contents if it only
 * consists in empty directories as a given user.
 * @flags: enum lttng_directory_handle_rmdir_recursive_flags
 */
int lttng_directory_handle_remove_subdirectory_recursive_as_user(
	const struct lttng_directory_handle *handle,
	const char *name,
	const struct lttng_credentials *creds,
	int flags);

/*
 * stat() a file relative to a directory handle.
 */
int lttng_directory_handle_stat(const struct lttng_directory_handle *handle,
				const char *name,
				struct stat *stat_buf);

/*
 * Returns true if this directory handle is backed by a file
 * descriptor, false otherwise.
 */
bool lttng_directory_handle_uses_fd(const struct lttng_directory_handle *handle);

/*
 * Compare two directory handles.
 *
 * Returns true if the two directory handles are equal, false otherwise.
 */
bool lttng_directory_handle_equals(const struct lttng_directory_handle *lhs,
				   const struct lttng_directory_handle *rhs);

#endif /* _COMPAT_PATH_HANDLE_H */
