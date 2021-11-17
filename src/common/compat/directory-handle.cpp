/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/compat/directory-handle.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/runas.hpp>
#include <common/credentials.hpp>
#include <lttng/constant.h>
#include <common/dynamic-array.hpp>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

/*
 * This compatibility layer shares a common "base" that is implemented
 * in terms of an internal API. This file contains two implementations
 * of the internal API below.
 */
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
int lttng_directory_handle_open(const struct lttng_directory_handle *handle,
		const char *filename, int flags, mode_t mode);
static
int _run_as_open(const struct lttng_directory_handle *handle,
		const char *filename,
		int flags, mode_t mode, uid_t uid, gid_t gid);
static
int lttng_directory_handle_unlink(
		const struct lttng_directory_handle *handle,
		const char *filename);
static
int _run_as_unlink(const struct lttng_directory_handle *handle,
		const char *filename, uid_t uid, gid_t gid);
static
int _lttng_directory_handle_rename(
		const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name);
static
int _run_as_rename(const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name, uid_t uid, gid_t gid);
static
DIR *lttng_directory_handle_opendir(const struct lttng_directory_handle *handle,
		const char *path);
static
int lttng_directory_handle_rmdir(
		const struct lttng_directory_handle *handle, const char *name);
static
int _run_as_rmdir(const struct lttng_directory_handle *handle,
		const char *name, uid_t uid, gid_t gid);
static
int _run_as_rmdir_recursive(
		const struct lttng_directory_handle *handle, const char *name,
		uid_t uid, gid_t gid, int flags);
static
void lttng_directory_handle_invalidate(struct lttng_directory_handle *handle);
static
void lttng_directory_handle_release(struct urcu_ref *ref);

#ifdef HAVE_DIRFD

/*
 * Special inode number reserved to represent the "current working directory".
 * ino_t is spec'ed as being an unsigned integral type.
 */
#define RESERVED_AT_FDCWD_INO                      \
	({                                         \
		uint64_t reserved_val;             \
		switch (sizeof(ino_t)) {           \
		case 4:                            \
			reserved_val = UINT32_MAX; \
			break;                     \
		case 8:                            \
			reserved_val = UINT64_MAX; \
			break;                     \
		default:                           \
			abort();                   \
		}                                  \
		(ino_t) reserved_val;              \
	})

struct lttng_directory_handle *lttng_directory_handle_create(const char *path)
{
	lttng_directory_handle cwd_handle {};
	cwd_handle.dirfd = AT_FDCWD;

	/* Open a handle to the CWD if NULL is passed. */
	return lttng_directory_handle_create_from_handle(path, &cwd_handle);
}

struct lttng_directory_handle *lttng_directory_handle_create_from_handle(
		const char *path,
		const struct lttng_directory_handle *ref_handle)
{
	int dirfd;
	struct lttng_directory_handle *handle = NULL;

	if (!path) {
		handle = lttng_directory_handle_copy(ref_handle);
		goto end;
	}
	if (!*path) {
		ERR("Failed to initialize directory handle: provided path is an empty string");
		goto end;
	}

	dirfd = openat(ref_handle->dirfd, path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd == -1) {
		PERROR("Failed to initialize directory handle to \"%s\"", path);
		goto end;
	}

	handle = lttng_directory_handle_create_from_dirfd(dirfd);
	if (!handle) {
		goto error_close;
	}
end:
	return handle;
error_close:
	if (close(dirfd)) {
		PERROR("Failed to close directory file descriptor");
	}
	return NULL;
}

struct lttng_directory_handle *lttng_directory_handle_create_from_dirfd(
		int dirfd)
{
	int ret;
	struct lttng_directory_handle *handle = zmalloc<lttng_directory_handle>();
	struct stat stat_buf;

	if (!handle) {
		goto end;
	}

	if (dirfd != AT_FDCWD) {
		ret = fstat(dirfd, &stat_buf);
		if (ret) {
			PERROR("Failed to fstat directory file descriptor %i", dirfd);
			lttng_directory_handle_release(&handle->ref);
			handle = NULL;
			goto end;
		}
	} else {
		handle->directory_inode = RESERVED_AT_FDCWD_INO;
	}
	handle->dirfd = dirfd;
	urcu_ref_init(&handle->ref);
end:
	return handle;
}

static
void lttng_directory_handle_release(struct urcu_ref *ref)
{
	int ret;
	struct lttng_directory_handle *handle =
			container_of(ref, struct lttng_directory_handle, ref);

	if (handle->destroy_cb) {
		handle->destroy_cb(handle, handle->destroy_cb_data);
	}

	if (handle->dirfd == AT_FDCWD || handle->dirfd == -1) {
		goto end;
	}
	ret = close(handle->dirfd);
	if (ret == -1) {
		PERROR("Failed to close directory file descriptor of directory handle");
	}
end:
	lttng_directory_handle_invalidate(handle);
	free(handle);
}

struct lttng_directory_handle *lttng_directory_handle_copy(
		const struct lttng_directory_handle *handle)
{
	struct lttng_directory_handle *new_handle = NULL;

	if (handle->dirfd == AT_FDCWD) {
		new_handle = lttng_directory_handle_create_from_dirfd(AT_FDCWD);
	} else {
		const int new_dirfd = dup(handle->dirfd);

		if (new_dirfd == -1) {
			PERROR("Failed to duplicate directory file descriptor of directory handle");
			goto end;
		}
		new_handle = lttng_directory_handle_create_from_dirfd(
				new_dirfd);
		if (!new_handle && close(new_dirfd)) {
			PERROR("Failed to close directory file descriptor of directory handle");
		}
	}
end:
	return new_handle;
}

bool lttng_directory_handle_equals(const struct lttng_directory_handle *lhs,
		const struct lttng_directory_handle *rhs)
{
	return lhs->directory_inode == rhs->directory_inode;
}

static
void lttng_directory_handle_invalidate(struct lttng_directory_handle *handle)
{
	handle->dirfd = -1;
}

int lttng_directory_handle_stat(const struct lttng_directory_handle *handle,
		const char *path, struct stat *st)
{
	return fstatat(handle->dirfd, path, st, 0);
}

bool lttng_directory_handle_uses_fd(
		const struct lttng_directory_handle *handle)
{
	return handle->dirfd != AT_FDCWD;
}

static
int lttng_directory_handle_mkdir(
		const struct lttng_directory_handle *handle,
		const char *path, mode_t mode)
{
	return mkdirat(handle->dirfd, path, mode);
}

static
int lttng_directory_handle_open(const struct lttng_directory_handle *handle,
		const char *filename, int flags, mode_t mode)
{
	return openat(handle->dirfd, filename, flags, mode);
}

static
int _run_as_open(const struct lttng_directory_handle *handle,
		const char *filename,
		int flags, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_openat(handle->dirfd, filename, flags, mode, uid, gid);
}

static
int _run_as_unlink(const struct lttng_directory_handle *handle,
		const char *filename, uid_t uid, gid_t gid)
{
	return run_as_unlinkat(handle->dirfd, filename, uid, gid);
}

static
int lttng_directory_handle_unlink(
		const struct lttng_directory_handle *handle,
		const char *filename)
{
	return unlinkat(handle->dirfd, filename, 0);
}

static
int _run_as_mkdir(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat(handle->dirfd, path, mode, uid, gid);
}

static
int _run_as_mkdir_recursive(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat_recursive(handle->dirfd, path, mode, uid, gid);
}

static
int _lttng_directory_handle_rename(
		const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name)
{
	return renameat(old_handle->dirfd, old_name,
			new_handle->dirfd, new_name);
}

static
int _run_as_rename(const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name, uid_t uid, gid_t gid)
{
	return run_as_renameat(old_handle->dirfd, old_name, new_handle->dirfd,
			new_name, uid, gid);
}

static
DIR *lttng_directory_handle_opendir(const struct lttng_directory_handle *handle,
		const char *path)
{
	DIR *dir_stream = NULL;
	int fd = openat(handle->dirfd, path, O_RDONLY);

	if (fd < 0) {
		goto end;
	}

	dir_stream = fdopendir(fd);
	if (!dir_stream) {
		int ret;

		PERROR("Failed to open directory stream");
		ret = close(fd);
		if (ret) {
			PERROR("Failed to close file descriptor to %s", path);
		}
		goto end;
	}

end:
	return dir_stream;
}

static
int lttng_directory_handle_rmdir(
		const struct lttng_directory_handle *handle, const char *name)
{
	int ret = unlinkat(handle->dirfd, name, AT_REMOVEDIR);
	if (ret) {
		PERROR("Failed to remove directory `%s`", name);
	}

	return ret;
}

static
int _run_as_rmdir(const struct lttng_directory_handle *handle,
		const char *name, uid_t uid, gid_t gid)
{
	return run_as_rmdirat(handle->dirfd, name, uid, gid);
}

static
int _run_as_rmdir_recursive(
		const struct lttng_directory_handle *handle, const char *name,
		uid_t uid, gid_t gid, int flags)
{
	return run_as_rmdirat_recursive(handle->dirfd, name, uid, gid, flags);
}

#else /* HAVE_DIRFD */

static
int get_full_path(const struct lttng_directory_handle *handle,
		const char *subdirectory, char *fullpath, size_t size)
{
	int ret;
	const bool subdirectory_is_absolute =
			subdirectory && *subdirectory == '/';
	const char * const base = subdirectory_is_absolute ?
			subdirectory : handle->base_path;
	const char * const end = subdirectory && !subdirectory_is_absolute ?
			subdirectory : NULL;
	const size_t base_len = strlen(base);
	const size_t end_len = end ? strlen(end) : 0;
	const bool add_separator_slash = end && base[base_len - 1] != '/';
	const bool add_trailing_slash = end && end[end_len - 1] != '/';

	ret = snprintf(fullpath, size, "%s%s%s%s",
			base,
			add_separator_slash ? "/" : "",
			end ? end : "",
			add_trailing_slash ? "/" : "");
	if (ret == -1 || ret >= size) {
		ERR("Failed to format subdirectory from directory handle");
		ret = -1;
		goto end;
	}
	ret = 0;
end:
	return ret;
}

static
struct lttng_directory_handle *_lttng_directory_handle_create(char *path)
{
	struct lttng_directory_handle *handle = zmalloc<lttng_directory_handle>();

	if (!handle) {
		goto end;
	}
	urcu_ref_init(&handle->ref);
	handle->base_path = path;
end:
	return handle;
}

struct lttng_directory_handle *lttng_directory_handle_create(
		const char *path)
{
	int ret;
	const char *cwd = "";
	size_t cwd_len, path_len;
	char cwd_buf[LTTNG_PATH_MAX] = {};
	char handle_buf[LTTNG_PATH_MAX] = {};
	struct lttng_directory_handle *new_handle = NULL;
	bool add_cwd_slash = false, add_trailing_slash = false;
	const struct lttng_directory_handle cwd_handle = {
		.base_path = handle_buf,
	};

	path_len = path ? strlen(path) : 0;
	add_trailing_slash = path && path[path_len - 1] != '/';
	if (!path || (path && *path != '/')) {
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
	}

	ret = snprintf(handle_buf, sizeof(handle_buf), "%s%s%s%s",
			cwd,
			add_cwd_slash ? "/" : "",
			path ? : "",
			add_trailing_slash ? "/" : "");
	if (ret == -1 || ret >= LTTNG_PATH_MAX) {
		ERR("Failed to initialize directory handle, failed to format directory path");
		goto end;
	}

	new_handle = lttng_directory_handle_create_from_handle(path, &cwd_handle);
end:
	return new_handle;
}

struct lttng_directory_handle *lttng_directory_handle_create_from_handle(
		const char *path,
		const struct lttng_directory_handle *ref_handle)
{
	int ret;
	size_t path_len, handle_path_len;
	bool add_trailing_slash;
	struct stat stat_buf;
	struct lttng_directory_handle *new_handle = NULL;
	char *new_path = NULL;

	LTTNG_ASSERT(ref_handle && ref_handle->base_path);

	ret = lttng_directory_handle_stat(ref_handle, path, &stat_buf);
	if (ret == -1) {
		PERROR("Failed to create directory handle");
		goto end;
	} else if (!S_ISDIR(stat_buf.st_mode)) {
		char full_path[LTTNG_PATH_MAX];

		/* Best effort for logging purposes. */
		ret = get_full_path(ref_handle, path, full_path,
				sizeof(full_path));
		if (ret) {
			full_path[0] = '\0';
		}

		ERR("Failed to initialize directory handle to \"%s\": not a directory",
				full_path);
		goto end;
	}
	if (!path) {
		new_handle = lttng_directory_handle_copy(ref_handle);
		goto end;
	}

	path_len = strlen(path);
	if (path_len == 0) {
		ERR("Failed to initialize directory handle: provided path is an empty string");
		ret = -1;
		goto end;
	}
	if (*path == '/') {
		new_path = strdup(path);
		if (!new_path) {
			goto end;
		}
		/* Takes ownership of new_path. */
		new_handle = _lttng_directory_handle_create(new_path);
		new_path = NULL;
		goto end;
	}

	add_trailing_slash = path[path_len - 1] != '/';

	handle_path_len = strlen(ref_handle->base_path) + path_len +
			!!add_trailing_slash;
	if (handle_path_len >= LTTNG_PATH_MAX) {
		ERR("Failed to initialize directory handle as the resulting path's length (%zu bytes) exceeds the maximal allowed length (%d bytes)",
				handle_path_len, LTTNG_PATH_MAX);
		goto end;
	}
	new_path = zmalloc<char>(handle_path_len);
	if (!new_path) {
		PERROR("Failed to initialize directory handle");
		goto end;
	}

	ret = sprintf(new_handle->base_path, "%s%s%s",
			ref_handle->base_path,
			path,
			add_trailing_slash ? "/" : "");
	if (ret == -1 || ret >= handle_path_len) {
		ERR("Failed to initialize directory handle: path formatting failed");
		goto end;
	}
	new_handle = _lttng_directory_handle_create(new_path);
	new_path = NULL;
end:
	free(new_path);
	return new_handle;
}

struct lttng_directory_handle *lttng_directory_handle_create_from_dirfd(
		int dirfd)
{
	LTTNG_ASSERT(dirfd == AT_FDCWD);
	return lttng_directory_handle_create(NULL);
}

static
void lttng_directory_handle_release(struct urcu_ref *ref)
{
	struct lttng_directory_handle *handle =
			container_of(ref, struct lttng_directory_handle, ref);

	free(handle->base_path);
	lttng_directory_handle_invalidate(handle);
	free(handle);
}

struct lttng_directory_handle *lttng_directory_handle_copy(
		const struct lttng_directory_handle *handle)
{
	struct lttng_directory_handle *new_handle = NULL;
	char *new_path = NULL;

	if (handle->base_path) {
		new_path = strdup(handle->base_path);
		if (!new_path) {
			goto end;
		}
	}
	new_handle = _lttng_directory_handle_create(new_path);
end:
	return new_handle;
}

bool lttng_directory_handle_equals(const struct lttng_directory_handle *lhs,
		const struct lttng_directory_handle *rhs)
{
	return strcmp(lhs->base_path, rhs->base_path) == 0;
}

static
void lttng_directory_handle_invalidate(struct lttng_directory_handle *handle)
{
	handle->base_path = NULL;
}

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

bool lttng_directory_handle_uses_fd(
		const struct lttng_directory_handle *handle)
{
	return false;
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
int lttng_directory_handle_open(const struct lttng_directory_handle *handle,
		const char *filename, int flags, mode_t mode)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, filename, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = open(fullpath, flags, mode);
end:
	return ret;
}

static
int lttng_directory_handle_unlink(
		const struct lttng_directory_handle *handle,
		const char *filename)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, filename, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = unlink(fullpath);
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
int _run_as_open(const struct lttng_directory_handle *handle,
		const char *filename,
		int flags, mode_t mode, uid_t uid, gid_t gid)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, filename, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = run_as_open(fullpath, flags, mode, uid, gid);
end:
	return ret;
}

static
int _run_as_unlink(const struct lttng_directory_handle *handle,
		const char *filename, uid_t uid, gid_t gid)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, filename, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = run_as_unlink(fullpath, uid, gid);
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

static
int _lttng_directory_handle_rename(
		const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name)
{
	int ret;
	char old_fullpath[LTTNG_PATH_MAX];
	char new_fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(old_handle, old_name, old_fullpath,
			sizeof(old_fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}
	ret = get_full_path(new_handle, new_name, new_fullpath,
			sizeof(new_fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = rename(old_fullpath, new_fullpath);
end:
	return ret;
}

static
int _run_as_rename(const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name, uid_t uid, gid_t gid)
{
	int ret;
	char old_fullpath[LTTNG_PATH_MAX];
	char new_fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(old_handle, old_name, old_fullpath,
			sizeof(old_fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}
	ret = get_full_path(new_handle, new_name, new_fullpath,
			sizeof(new_fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = run_as_rename(old_fullpath, new_fullpath, uid, gid);
end:
	return ret;
}

static
DIR *lttng_directory_handle_opendir(const struct lttng_directory_handle *handle,
		const char *path)
{
	int ret;
	DIR *dir_stream = NULL;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, path, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	dir_stream = opendir(fullpath);
end:
	return dir_stream;
}

static
int lttng_directory_handle_rmdir(
		const struct lttng_directory_handle *handle, const char *name)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, name, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = rmdir(fullpath);
end:
	return ret;
}

static
int _run_as_rmdir(const struct lttng_directory_handle *handle,
		const char *name, uid_t uid, gid_t gid)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, name, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = run_as_rmdir(fullpath, uid, gid);
end:
	return ret;
}

static
int _run_as_rmdir_recursive(
		const struct lttng_directory_handle *handle, const char *name,
		uid_t uid, gid_t gid, int flags)
{
	int ret;
	char fullpath[LTTNG_PATH_MAX];

	ret = get_full_path(handle, name, fullpath, sizeof(fullpath));
	if (ret) {
		errno = ENOMEM;
		goto end;
	}

	ret = run_as_rmdir_recursive(fullpath, uid, gid, flags);
end:
	return ret;
}

#endif /* HAVE_DIRFD */

/* Common implementation. */

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
	} else if (errno != ENOENT) {
		goto end;
	}

	/*
	 * Let mkdir handle other errors as the caller expects mkdir
	 * semantics.
	 */
	ret = lttng_directory_handle_mkdir(handle, path, mode);
end:
	return ret;
}

static
int create_directory_recursive(const struct lttng_directory_handle *handle,
		const char *path, mode_t mode)
{
	char *p, tmp[LTTNG_PATH_MAX];
	size_t len;
	int ret;

	LTTNG_ASSERT(path);

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

bool lttng_directory_handle_get(struct lttng_directory_handle *handle)
{
	return urcu_ref_get_unless_zero(&handle->ref);
}

void lttng_directory_handle_put(struct lttng_directory_handle *handle)
{
	if (!handle) {
		return;
	}
	LTTNG_ASSERT(handle->ref.refcount);
	urcu_ref_put(&handle->ref, lttng_directory_handle_release);
}

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
		ret = _run_as_mkdir(handle, subdirectory, mode,
				lttng_credentials_get_uid(creds),
				lttng_credentials_get_gid(creds));
	}

	return ret;
}

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
				mode, lttng_credentials_get_uid(creds), lttng_credentials_get_gid(creds));
	}

	return ret;
}

int lttng_directory_handle_create_subdirectory(
		const struct lttng_directory_handle *handle,
		const char *subdirectory,
		mode_t mode)
{
	return lttng_directory_handle_create_subdirectory_as_user(
			handle, subdirectory, mode, NULL);
}

int lttng_directory_handle_create_subdirectory_recursive(
		const struct lttng_directory_handle *handle,
		const char *subdirectory_path,
		mode_t mode)
{
	return lttng_directory_handle_create_subdirectory_recursive_as_user(
			handle, subdirectory_path, mode, NULL);
}

int lttng_directory_handle_open_file_as_user(
		const struct lttng_directory_handle *handle,
		const char *filename,
		int flags, mode_t mode,
		const struct lttng_credentials *creds)
{
	int ret;

	if (!creds) {
		/* Run as current user. */
		ret = lttng_directory_handle_open(handle, filename, flags,
				mode);
	} else {
		ret = _run_as_open(handle, filename, flags, mode,
				lttng_credentials_get_uid(creds), lttng_credentials_get_gid(creds));
	}
	return ret;
}

int lttng_directory_handle_open_file(
		const struct lttng_directory_handle *handle,
		const char *filename,
		int flags, mode_t mode)
{
	return lttng_directory_handle_open_file_as_user(handle, filename, flags,
			mode, NULL);
}

int lttng_directory_handle_unlink_file_as_user(
		const struct lttng_directory_handle *handle,
		const char *filename,
		const struct lttng_credentials *creds)
{
	int ret;

	if (!creds) {
		/* Run as current user. */
		ret = lttng_directory_handle_unlink(handle, filename);
	} else {
		ret = _run_as_unlink(handle, filename, lttng_credentials_get_uid(creds), lttng_credentials_get_gid(creds));
	}
	return ret;
}

int lttng_directory_handle_unlink_file(
		const struct lttng_directory_handle *handle,
		const char *filename)
{
	return lttng_directory_handle_unlink_file_as_user(handle,
			filename, NULL);
}

int lttng_directory_handle_rename(
		const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name)
{
	return lttng_directory_handle_rename_as_user(old_handle, old_name,
			new_handle, new_name, NULL);
}

int lttng_directory_handle_rename_as_user(
		const struct lttng_directory_handle *old_handle,
		const char *old_name,
		const struct lttng_directory_handle *new_handle,
		const char *new_name,
		const struct lttng_credentials *creds)
{
	int ret;

	if (!creds) {
		/* Run as current user. */
		ret = _lttng_directory_handle_rename(old_handle,
				old_name, new_handle, new_name);
	} else {
		ret = _run_as_rename(old_handle, old_name, new_handle,
				new_name, lttng_credentials_get_uid(creds), lttng_credentials_get_gid(creds));
	}
	return ret;
}

int lttng_directory_handle_remove_subdirectory(
		const struct lttng_directory_handle *handle,
		const char *name)
{
	return lttng_directory_handle_remove_subdirectory_as_user(handle, name,
			NULL);
}

int lttng_directory_handle_remove_subdirectory_as_user(
		const struct lttng_directory_handle *handle,
		const char *name,
		const struct lttng_credentials *creds)
{
	int ret;

	if (!creds) {
		/* Run as current user. */
		ret = lttng_directory_handle_rmdir(handle, name);
	} else {
		ret = _run_as_rmdir(handle, name, lttng_credentials_get_uid(creds), lttng_credentials_get_gid(creds));
	}
	return ret;
}

struct rmdir_frame {
	ssize_t parent_frame_idx;
	DIR *dir;
	bool empty;
	/* Size including '\0'. */
	size_t path_size;
};

static
void rmdir_frame_fini(void *data)
{
	int ret;
	struct rmdir_frame *frame = (rmdir_frame *) data;

	ret = closedir(frame->dir);
	if (ret == -1) {
		PERROR("Failed to close directory stream");
	}
}

static
int remove_directory_recursive(const struct lttng_directory_handle *handle,
		const char *path, int flags)
{
	int ret;
	struct lttng_dynamic_array frames;
	size_t current_frame_idx = 0;
	struct rmdir_frame initial_frame = {
		.parent_frame_idx = -1,
		.dir = lttng_directory_handle_opendir(handle, path),
		.empty = true,
		.path_size = strlen(path) + 1,
	};
	struct lttng_dynamic_buffer current_path;
	const char separator = '/';

	lttng_dynamic_buffer_init(&current_path);
	lttng_dynamic_array_init(&frames, sizeof(struct rmdir_frame),
			rmdir_frame_fini);

	if (flags & ~(LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG |
				    LTTNG_DIRECTORY_HANDLE_FAIL_NON_EMPTY_FLAG)) {
		ERR("Unknown flags %d", flags);
		ret = -1;
		goto end;
	}

	if (!initial_frame.dir) {
		if (flags & LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG &&
				errno == ENOENT) {
			DBG("Cannot rmdir \"%s\": root does not exist", path);
			ret = 0;
			goto end;
		} else {
			PERROR("Failed to rmdir \"%s\"", path);
			ret = -1;
			goto end;
		}
	}

	ret = lttng_dynamic_array_add_element(&frames, &initial_frame);
	if (ret) {
		ERR("Failed to push context frame during recursive directory removal");
		rmdir_frame_fini(&initial_frame);
		goto end;
	}

	ret = lttng_dynamic_buffer_append(
			&current_path, path, initial_frame.path_size);
	if (ret) {
		ERR("Failed to set initial path during recursive directory removal");
		ret = -1;
		goto end;
	}

	while (lttng_dynamic_array_get_count(&frames) > 0) {
		struct dirent *entry;
		struct rmdir_frame *current_frame =
				(rmdir_frame *) lttng_dynamic_array_get_element(
						&frames, current_frame_idx);

		LTTNG_ASSERT(current_frame->dir);
		ret = lttng_dynamic_buffer_set_size(
				&current_path, current_frame->path_size);
		LTTNG_ASSERT(!ret);
		current_path.data[current_path.size - 1] = '\0';

		while ((entry = readdir(current_frame->dir))) {
			struct stat st;

			if (!strcmp(entry->d_name, ".") ||
					!strcmp(entry->d_name, "..")) {
				continue;
			}

			/* Set current_path to the entry's path. */
			ret = lttng_dynamic_buffer_set_size(
					&current_path, current_path.size - 1);
			LTTNG_ASSERT(!ret);
			ret = lttng_dynamic_buffer_append(&current_path,
					&separator, sizeof(separator));
			if (ret) {
				goto end;
			}
			ret = lttng_dynamic_buffer_append(&current_path,
					entry->d_name,
					strlen(entry->d_name) + 1);
			if (ret) {
				goto end;
			}

			if (lttng_directory_handle_stat(
					    handle, current_path.data, &st)) {
				if ((flags & LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG) &&
						errno == ENOENT) {
					break;
				}
				PERROR("Failed to stat \"%s\"",
						current_path.data);
				ret = -1;
				goto end;
			}

			if (!S_ISDIR(st.st_mode)) {
				if (flags & LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG) {
					current_frame->empty = false;
					break;
				} else {
					/* Not empty, abort. */
					DBG("Directory \"%s\" is not empty; refusing to remove directory",
							current_path.data);
					ret = -1;
					goto end;
				}
			} else {
				struct rmdir_frame new_frame = {
					.parent_frame_idx = (ssize_t) current_frame_idx,
					.dir = lttng_directory_handle_opendir(
							handle,
							current_path.data),
					.empty = true,
					.path_size = current_path.size,
				};

				if (!new_frame.dir) {
					if (flags & LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG &&
							errno == ENOENT) {
						DBG("Non-existing directory stream during recursive directory removal");
						break;
					} else {
						PERROR("Failed to open directory stream during recursive directory removal");
						ret = -1;
						goto end;
					}
				}
				ret = lttng_dynamic_array_add_element(
						&frames, &new_frame);
				if (ret) {
					ERR("Failed to push context frame during recursive directory removal");
					rmdir_frame_fini(&new_frame);
					goto end;
				}
				current_frame_idx++;
				/* We break iteration on readdir. */
				break;
			}
		}
		if (entry) {
			continue;
		}

		/* Pop rmdir frame. */
		if (current_frame->empty) {
			ret = lttng_directory_handle_rmdir(
					handle, current_path.data);
			if (ret) {
				if ((flags & LTTNG_DIRECTORY_HANDLE_FAIL_NON_EMPTY_FLAG) ||
						errno != ENOENT) {
					PERROR("Failed to remove \"%s\" during recursive directory removal",
							current_path.data);
					goto end;
				}
				DBG("Non-existing directory stream during recursive directory removal");
			}
		} else if (current_frame->parent_frame_idx >= 0) {
			struct rmdir_frame *parent_frame;

			parent_frame = (rmdir_frame *) lttng_dynamic_array_get_element(&frames,
					current_frame->parent_frame_idx);
			LTTNG_ASSERT(parent_frame);
			parent_frame->empty = false;
		}
		ret = lttng_dynamic_array_remove_element(
				&frames, current_frame_idx);
		if (ret) {
			ERR("Failed to pop context frame during recursive directory removal");
			goto end;
		}
		current_frame_idx--;
	}
end:
	lttng_dynamic_array_reset(&frames);
	lttng_dynamic_buffer_reset(&current_path);
	return ret;
}

int lttng_directory_handle_remove_subdirectory_recursive(
		const struct lttng_directory_handle *handle,
		const char *name,
		int flags)
{
	return lttng_directory_handle_remove_subdirectory_recursive_as_user(
			handle, name, NULL, flags);
}

int lttng_directory_handle_remove_subdirectory_recursive_as_user(
		const struct lttng_directory_handle *handle,
		const char *name,
		const struct lttng_credentials *creds,
		int flags)
{
	int ret;

	if (!creds) {
		/* Run as current user. */
		ret = remove_directory_recursive(handle, name, flags);
	} else {
		ret = _run_as_rmdir_recursive(handle, name, lttng_credentials_get_uid(creds),
				lttng_credentials_get_gid(creds), flags);
	}
	return ret;
}
