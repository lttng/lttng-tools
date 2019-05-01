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

#include <common/compat/directory-handle.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/runas.h>
#include <common/credentials.h>
#include <lttng/constant.h>

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static
int lttng_directory_handle_stat(const struct lttng_directory_handle *handle,
		const char *path, struct stat *st);
static
int lttng_directory_handle_mkdir(
		const struct lttng_directory_handle *handle,
		const char *path, mode_t mode);
static
int _run_as_mkdir(const struct lttng_directory_handle *handle, const char *path,
		mode_t mode, uid_t uid, gid_t gid);
static
int _run_as_mkdir_recursive(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode, uid_t uid, gid_t gid);
static
void lttng_directory_handle_invalidate(struct lttng_directory_handle *handle);

#ifdef COMPAT_DIRFD

LTTNG_HIDDEN
int lttng_directory_handle_init(struct lttng_directory_handle *new_handle,
		const char *path)
{
	const struct lttng_directory_handle cwd_handle = {
		.dirfd = AT_FDCWD,
	};

	/* Open a handle to the CWD if NULL is passed. */
	return lttng_directory_handle_init_from_handle(new_handle,
			path,
			&cwd_handle);
}

LTTNG_HIDDEN
int lttng_directory_handle_init_from_handle(
		struct lttng_directory_handle *new_handle, const char *path,
		const struct lttng_directory_handle *handle)
{
	int ret;

	if (!path) {
		ret = lttng_directory_handle_copy(handle, new_handle);
		goto end;
	}
	if (!*path) {
		ERR("Failed to initialize directory handle: provided path is an empty string");
		ret = -1;
		goto end;
	}
	ret = openat(handle->dirfd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (ret == -1) {
		PERROR("Failed to initialize directory handle to \"%s\"", path);
		goto end;
	}
	new_handle->dirfd = ret;
	ret = 0;
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_directory_handle_init_from_dirfd(
		struct lttng_directory_handle *handle, int dirfd)
{
	handle->dirfd = dirfd;
	return 0;
}

LTTNG_HIDDEN
void lttng_directory_handle_fini(struct lttng_directory_handle *handle)
{
	int ret;

	if (handle->dirfd == AT_FDCWD || handle->dirfd == -1) {
		goto end;
	}
	ret = close(handle->dirfd);
	if (ret == -1) {
		PERROR("Failed to close directory file descriptor of directory handle");
	}
end:
	lttng_directory_handle_invalidate(handle);
}

LTTNG_HIDDEN
int lttng_directory_handle_copy(const struct lttng_directory_handle *handle,
		struct lttng_directory_handle *new_copy)
{
	int ret = 0;

	if (handle->dirfd == AT_FDCWD) {
		new_copy->dirfd = handle->dirfd;
	} else {
		new_copy->dirfd = dup(handle->dirfd);
		if (new_copy->dirfd == -1) {
			PERROR("Failed to duplicate directory fd of directory handle");
			ret = -1;
		}
	}
	return ret;
}

static
void lttng_directory_handle_invalidate(struct lttng_directory_handle *handle)
{
	handle->dirfd = -1;
}

static
int lttng_directory_handle_stat(const struct lttng_directory_handle *handle,
		const char *path, struct stat *st)
{
	return fstatat(handle->dirfd, path, st, 0);
}

static
int lttng_directory_handle_mkdir(
		const struct lttng_directory_handle *handle,
		const char *path, mode_t mode)
{
	return mkdirat(handle->dirfd, path, mode);
}

static
int _run_as_mkdir(const struct lttng_directory_handle *handle, const char *path,
		mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat(handle->dirfd, path, mode, uid, gid);
}

static
int _run_as_mkdir_recursive(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat_recursive(handle->dirfd, path, mode, uid, gid);
}

#else /* COMPAT_DIRFD */

static
int get_full_path(const struct lttng_directory_handle *handle,
		const char *subdirectory, char *fullpath, size_t size)
{
	int ret;

	subdirectory = subdirectory ? : "";
	/*
	 * Don't include the base path if subdirectory is absolute.
	 * This is the same behaviour than mkdirat.
	 */
	ret = snprintf(fullpath, size, "%s%s",
			*subdirectory != '/' ? handle->base_path : "",
			subdirectory);
	if (ret == -1 || ret >= size) {
		ERR("Failed to format subdirectory from directory handle");
		ret = -1;
	}
	ret = 0;
	return ret;
}

LTTNG_HIDDEN
int lttng_directory_handle_init(struct lttng_directory_handle *handle,
		const char *path)
{
	int ret;
	const char *cwd;
	size_t cwd_len, path_len;
	char cwd_buf[LTTNG_PATH_MAX] = {};
	char handle_buf[LTTNG_PATH_MAX] = {};
	bool add_cwd_slash, add_trailing_slash;
	const struct lttng_directory_handle cwd_handle = {
		.base_path = handle_buf,
	};

	if (path && *path == '/') {
		/*
		 * Creation of an handle to an absolute path; no need to sample
		 * the cwd.
		 */
		goto create;
	}
	path_len = path ? strlen(path) : 0;

	cwd = getcwd(cwd_buf, sizeof(cwd_buf));
	if (!cwd) {
		PERROR("Failed to initialize directory handle, can't get current working directory");
		ret = -1;
		goto end;
	}
	cwd_len = strlen(cwd);
	if (cwd_len == 0) {
		ERR("Failed to initialize directory handle, current working directory path has a length of 0");
		ret = -1;
		goto end;
	}

	add_cwd_slash = cwd[cwd_len - 1] != '/';
	add_trailing_slash = path && path[path_len - 1] != '/';

	ret = snprintf(handle_buf, sizeof(handle_buf), "%s%s%s%s",
			cwd,
			add_cwd_slash ? "/" : "",
			path ? : "",
			add_trailing_slash ? "/" : "");
	if (ret == -1 || ret >= LTTNG_PATH_MAX) {
		ERR("Failed to initialize directory handle, failed to format directory path");
		goto end;
	}
create:
	ret = lttng_directory_handle_init_from_handle(handle, path,
			&cwd_handle);
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_directory_handle_init_from_handle(
		struct lttng_directory_handle *new_handle, const char *path,
		const struct lttng_directory_handle *handle)
{
	int ret;
	size_t path_len, handle_path_len;
	bool add_trailing_slash;
	struct stat stat_buf;

	assert(handle && handle->base_path);

	ret = lttng_directory_handle_stat(handle, path, &stat_buf);
	if (ret == -1) {
		PERROR("Failed to create directory handle");
		goto end;
	} else if (!S_ISDIR(stat_buf.st_mode)) {
		char full_path[LTTNG_PATH_MAX];

		/* Best effort for logging purposes. */
		ret = get_full_path(handle, path, full_path,
				sizeof(full_path));
		if (ret) {
			full_path[0] = '\0';
		}

		ERR("Failed to initialize directory handle to \"%s\": not a directory",
				full_path);
		ret = -1;
		goto end;
	}
	if (!path) {
		ret = lttng_directory_handle_copy(handle, new_handle);
		goto end;
	}

	path_len = strlen(path);
	if (path_len == 0) {
		ERR("Failed to initialize directory handle: provided path is an empty string");
		ret = -1;
		goto end;
	}
	if (*path == '/') {
		new_handle->base_path = strdup(path);
		ret = new_handle->base_path ? 0 : -1;
		goto end;
	}

	add_trailing_slash = path[path_len - 1] != '/';

	handle_path_len = strlen(handle->base_path) + path_len +
			!!add_trailing_slash;
	if (handle_path_len >= LTTNG_PATH_MAX) {
		ERR("Failed to initialize directory handle as the resulting path's length (%zu bytes) exceeds the maximal allowed length (%d bytes)",
				handle_path_len, LTTNG_PATH_MAX);
		ret = -1;
		goto end;
	}
	new_handle->base_path = zmalloc(handle_path_len);
	if (!new_handle->base_path) {
		PERROR("Failed to initialize directory handle");
		ret = -1;
		goto end;
	}

	ret = sprintf(new_handle->base_path, "%s%s%s",
			handle->base_path,
			path,
			add_trailing_slash ? "/" : "");
	if (ret == -1 || ret >= handle_path_len) {
		ERR("Failed to initialize directory handle: path formatting failed");
		ret = -1;
		goto end;
	}
end:
	return ret;
}

LTTNG_HIDDEN
int lttng_directory_handle_init_from_dirfd(
		struct lttng_directory_handle *handle, int dirfd)
{
	assert(dirfd == AT_FDCWD);
	return lttng_directory_handle_init(handle, NULL);
}

LTTNG_HIDDEN
void lttng_directory_handle_fini(struct lttng_directory_handle *handle)
{
	free(handle->base_path);
	lttng_directory_handle_invalidate(handle);
}

LTTNG_HIDDEN
int lttng_directory_handle_copy(const struct lttng_directory_handle *handle,
		struct lttng_directory_handle *new_copy)
{
	new_copy->base_path = strdup(handle->base_path);
	return new_copy->base_path ? 0 : -1;
}

static
void lttng_directory_handle_invalidate(struct lttng_directory_handle *handle)
{
	handle->base_path = NULL;
}

static
int lttng_directory_handle_stat(const struct lttng_directory_handle *handle,
		const char *subdirectory, struct stat *st)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, subdirectory, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = stat(fullpath, st);
end:
	return ret;
}

static
int lttng_directory_handle_mkdir(const struct lttng_directory_handle *handle,
		const char *subdirectory, mode_t mode)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, subdirectory, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = mkdir(fullpath, mode);
end:
	return ret;
}

static
int _run_as_mkdir(const struct lttng_directory_handle *handle, const char *path,
		mode_t mode, uid_t uid, gid_t gid)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, path, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = run_as_mkdir(fullpath, mode, uid, gid);
end:
	return ret;
}

static
int _run_as_mkdir_recursive(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, path, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = run_as_mkdir_recursive(fullpath, mode, uid, gid);
end:
	return ret;
}

#endif /* COMPAT_DIRFD */

/*
 * On some filesystems (e.g. nfs), mkdir will validate access rights before
 * checking for the existence of the path element. This means that on a setup
 * where "/home/" is a mounted NFS share, and running as an unpriviledged user,
 * recursively creating a path of the form "/home/my_user/trace/" will fail with
 * EACCES on mkdir("/home", ...).
 *
 * Checking the path for existence allows us to work around this behaviour.
 */
static
int create_directory_check_exists(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode)
{
	int ret = 0;
	struct stat st;

	ret = lttng_directory_handle_stat(handle, path, &st);
	if (ret == 0) {
		if (S_ISDIR(st.st_mode)) {
			/* Directory exists, skip. */
			goto end;
		} else {
			/* Exists, but is not a directory. */
			errno = ENOTDIR;
			ret = -1;
			goto end;
		}
	}

	/*
	 * Let mkdir handle other errors as the caller expects mkdir
	 * semantics.
	 */
	ret = lttng_directory_handle_mkdir(handle, path, mode);
end:
	return ret;
}

/* Common implementation. */
LTTNG_HIDDEN
struct lttng_directory_handle
lttng_directory_handle_move(struct lttng_directory_handle *original)
{
	const struct lttng_directory_handle tmp = *original;

	lttng_directory_handle_invalidate(original);
	return tmp;
}

static
int create_directory_recursive(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode)
{
	char *p, tmp[LTTNG_PATH_MAX];
	size_t len;
	int ret;

	assert(path);

	ret = lttng_strncpy(tmp, path, sizeof(tmp));
	if (ret) {
		ERR("Failed to create directory: provided path's length (%zu bytes) exceeds the maximal allowed length (%zu bytes)",
				strlen(path) + 1, sizeof(tmp));
		goto error;
	}

	len = strlen(path);
	if (tmp[len - 1] == '/') {
		tmp[len - 1] = 0;
	}

	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			if (tmp[strlen(tmp) - 1] == '.' &&
					tmp[strlen(tmp) - 2] == '.' &&
					tmp[strlen(tmp) - 3] == '/') {
				ERR("Using '/../' is not permitted in the trace path (%s)",
						tmp);
				ret = -1;
				goto error;
			}
			ret = create_directory_check_exists(handle, tmp, mode);
			if (ret < 0) {
				if (errno != EACCES) {
					PERROR("Failed to create directory \"%s\"",
							path);
					ret = -errno;
					goto error;
				}
			}
			*p = '/';
		}
	}

	ret = create_directory_check_exists(handle, tmp, mode);
	if (ret < 0) {
		PERROR("mkdirat recursive last element");
		ret = -errno;
	}
error:
	return ret;
}

LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory_as_user(
		const struct lttng_directory_handle *handle,
		const char *subdirectory,
		mode_t mode, const struct lttng_credentials *creds)
{
	int ret;

	if (!creds) {
		/* Run as current user. */
		ret = create_directory_check_exists(handle,
				subdirectory, mode);
	} else {
		ret = _run_as_mkdir(handle, subdirectory,
				mode, creds->uid, creds->gid);
	}

	return ret;
}

LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory_recursive_as_user(
		const struct lttng_directory_handle *handle,
		const char *subdirectory_path,
		mode_t mode, const struct lttng_credentials *creds)
{
	int ret;

	if (!creds) {
		/* Run as current user. */
		ret = create_directory_recursive(handle,
				subdirectory_path, mode);
	} else {
		ret = _run_as_mkdir_recursive(handle, subdirectory_path,
				mode, creds->uid, creds->gid);
	}

	return ret;
}

LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory(
		const struct lttng_directory_handle *handle,
		const char *subdirectory,
		mode_t mode)
{
	return lttng_directory_handle_create_subdirectory_as_user(
			handle, subdirectory, mode, NULL);
}

LTTNG_HIDDEN
int lttng_directory_handle_create_subdirectory_recursive(
		const struct lttng_directory_handle *handle,
		const char *subdirectory_path,
		mode_t mode)
{
	return lttng_directory_handle_create_subdirectory_recursive_as_user(
			handle, subdirectory_path, mode, NULL);
}
