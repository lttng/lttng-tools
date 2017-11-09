/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 - Raphaël Beamonte <raphael.beamonte@gmail.com>
 * Copyright (C) 2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <grp.h>
#include <pwd.h>
#include <sys/file.h>
#include <unistd.h>

#include <common/common.h>
#include <common/runas.h>
#include <common/compat/getenv.h>
#include <common/compat/string.h>
#include <common/compat/dirent.h>
#include <lttng/constant.h>

#include "utils.h"
#include "defaults.h"

/*
 * Return a partial realpath(3) of the path even if the full path does not
 * exist. For instance, with /tmp/test1/test2/test3, if test2/ does not exist
 * but the /tmp/test1 does, the real path for /tmp/test1 is concatened with
 * /test2/test3 then returned. In normal time, realpath(3) fails if the end
 * point directory does not exist.
 * In case resolved_path is NULL, the string returned was allocated in the
 * function and thus need to be freed by the caller. The size argument allows
 * to specify the size of the resolved_path argument if given, or the size to
 * allocate.
 */
LTTNG_HIDDEN
char *utils_partial_realpath(const char *path, char *resolved_path, size_t size)
{
	char *cut_path = NULL, *try_path = NULL, *try_path_prev = NULL;
	const char *next, *prev, *end;

	/* Safety net */
	if (path == NULL) {
		goto error;
	}

	/*
	 * Identify the end of the path, we don't want to treat the
	 * last char if it is a '/', we will just keep it on the side
	 * to be added at the end, and return a value coherent with
	 * the path given as argument
	 */
	end = path + strlen(path);
	if (*(end-1) == '/') {
		end--;
	}

	/* Initiate the values of the pointers before looping */
	next = path;
	prev = next;
	/* Only to ensure try_path is not NULL to enter the while */
	try_path = (char *)next;

	/* Resolve the canonical path of the first part of the path */
	while (try_path != NULL && next != end) {
		char *try_path_buf = NULL;

		/*
		 * If there is not any '/' left, we want to try with
		 * the full path
		 */
		next = strpbrk(next + 1, "/");
		if (next == NULL) {
			next = end;
		}

		/* Cut the part we will be trying to resolve */
		cut_path = lttng_strndup(path, next - path);
		if (cut_path == NULL) {
			PERROR("lttng_strndup");
			goto error;
		}

		try_path_buf = zmalloc(LTTNG_PATH_MAX);
		if (!try_path_buf) {
			PERROR("zmalloc");
			goto error;
		}

		/* Try to resolve this part */
		try_path = realpath((char *) cut_path, try_path_buf);
		if (try_path == NULL) {
			free(try_path_buf);
			/*
			 * There was an error, we just want to be assured it
			 * is linked to an unexistent directory, if it's another
			 * reason, we spawn an error
			 */
			switch (errno) {
			case ENOENT:
				/* Ignore the error */
				break;
			default:
				PERROR("realpath (partial_realpath)");
				goto error;
				break;
			}
		} else {
			/* Save the place we are before trying the next step */
			try_path_buf = NULL;
			free(try_path_prev);
			try_path_prev = try_path;
			prev = next;
		}

		/* Free the allocated memory */
		free(cut_path);
		cut_path = NULL;
	}

	/* Allocate memory for the resolved path if necessary */
	if (resolved_path == NULL) {
		resolved_path = zmalloc(size);
		if (resolved_path == NULL) {
			PERROR("zmalloc resolved path");
			goto error;
		}
	}

	/*
	 * If we were able to solve at least partially the path, we can concatenate
	 * what worked and what didn't work
	 */
	if (try_path_prev != NULL) {
		/* If we risk to concatenate two '/', we remove one of them */
		if (try_path_prev[strlen(try_path_prev) - 1] == '/' && prev[0] == '/') {
			try_path_prev[strlen(try_path_prev) - 1] = '\0';
		}

		/*
		 * Duplicate the memory used by prev in case resolved_path and
		 * path are pointers for the same memory space
		 */
		cut_path = strdup(prev);
		if (cut_path == NULL) {
			PERROR("strdup");
			goto error;
		}

		/* Concatenate the strings */
		snprintf(resolved_path, size, "%s%s", try_path_prev, cut_path);

		/* Free the allocated memory */
		free(cut_path);
		free(try_path_prev);
		cut_path = NULL;
		try_path_prev = NULL;
	/*
	 * Else, we just copy the path in our resolved_path to
	 * return it as is
	 */
	} else {
		strncpy(resolved_path, path, size);
	}

	/* Then we return the 'partially' resolved path */
	return resolved_path;

error:
	free(resolved_path);
	free(cut_path);
	free(try_path);
	if (try_path_prev != try_path) {
		free(try_path_prev);
	}
	return NULL;
}

/*
 * Make a full resolution of the given path even if it doesn't exist.
 * This function uses the utils_partial_realpath function to resolve
 * symlinks and relatives paths at the start of the string, and
 * implements functionnalities to resolve the './' and '../' strings
 * in the middle of a path. This function is only necessary because
 * realpath(3) does not accept to resolve unexistent paths.
 * The returned string was allocated in the function, it is thus of
 * the responsibility of the caller to free this memory.
 */
LTTNG_HIDDEN
char *utils_expand_path(const char *path)
{
	char *next, *previous, *slash, *start_path, *absolute_path = NULL;
	char *last_token;
	int is_dot, is_dotdot;

	/* Safety net */
	if (path == NULL) {
		goto error;
	}

	/* Allocate memory for the absolute_path */
	absolute_path = zmalloc(PATH_MAX);
	if (absolute_path == NULL) {
		PERROR("zmalloc expand path");
		goto error;
	}

	/*
	 * If the path is not already absolute nor explicitly relative,
	 * consider we're in the current directory
	 */
	if (*path != '/' && strncmp(path, "./", 2) != 0 &&
			strncmp(path, "../", 3) != 0) {
		snprintf(absolute_path, PATH_MAX, "./%s", path);
	/* Else, we just copy the path */
	} else {
		strncpy(absolute_path, path, PATH_MAX);
	}

	/* Resolve partially our path */
	absolute_path = utils_partial_realpath(absolute_path,
			absolute_path, PATH_MAX);

	/* As long as we find '/./' in the working_path string */
	while ((next = strstr(absolute_path, "/./"))) {

		/* We prepare the start_path not containing it */
		start_path = lttng_strndup(absolute_path, next - absolute_path);
		if (!start_path) {
			PERROR("lttng_strndup");
			goto error;
		}
		/* And we concatenate it with the part after this string */
		snprintf(absolute_path, PATH_MAX, "%s%s", start_path, next + 2);

		free(start_path);
	}

	/* As long as we find '/../' in the working_path string */
	while ((next = strstr(absolute_path, "/../"))) {
		/* We find the last level of directory */
		previous = absolute_path;
		while ((slash = strpbrk(previous, "/")) && slash != next) {
			previous = slash + 1;
		}

		/* Then we prepare the start_path not containing it */
		start_path = lttng_strndup(absolute_path, previous - absolute_path);
		if (!start_path) {
			PERROR("lttng_strndup");
			goto error;
		}

		/* And we concatenate it with the part after the '/../' */
		snprintf(absolute_path, PATH_MAX, "%s%s", start_path, next + 4);

		/* We can free the memory used for the start path*/
		free(start_path);

		/* Then we verify for symlinks using partial_realpath */
		absolute_path = utils_partial_realpath(absolute_path,
				absolute_path, PATH_MAX);
	}

	/* Identify the last token */
	last_token = strrchr(absolute_path, '/');

	/* Verify that this token is not a relative path */
	is_dotdot = (strcmp(last_token, "/..") == 0);
	is_dot = (strcmp(last_token, "/.") == 0);

	/* If it is, take action */
	if (is_dot || is_dotdot) {
		/* For both, remove this token */
		*last_token = '\0';

		/* If it was a reference to parent directory, go back one more time */
		if (is_dotdot) {
			last_token = strrchr(absolute_path, '/');

			/* If there was only one level left, we keep the first '/' */
			if (last_token == absolute_path) {
				last_token++;
			}

			*last_token = '\0';
		}
	}

	return absolute_path;

error:
	free(absolute_path);
	return NULL;
}

/*
 * Create a pipe in dst.
 */
LTTNG_HIDDEN
int utils_create_pipe(int *dst)
{
	int ret;

	if (dst == NULL) {
		return -1;
	}

	ret = pipe(dst);
	if (ret < 0) {
		PERROR("create pipe");
	}

	return ret;
}

/*
 * Create pipe and set CLOEXEC flag to both fd.
 *
 * Make sure the pipe opened by this function are closed at some point. Use
 * utils_close_pipe().
 */
LTTNG_HIDDEN
int utils_create_pipe_cloexec(int *dst)
{
	int ret, i;

	if (dst == NULL) {
		return -1;
	}

	ret = utils_create_pipe(dst);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = fcntl(dst[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl pipe cloexec");
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Create pipe and set fd flags to FD_CLOEXEC and O_NONBLOCK.
 *
 * Make sure the pipe opened by this function are closed at some point. Use
 * utils_close_pipe(). Using pipe() and fcntl rather than pipe2() to
 * support OSes other than Linux 2.6.23+.
 */
LTTNG_HIDDEN
int utils_create_pipe_cloexec_nonblock(int *dst)
{
	int ret, i;

	if (dst == NULL) {
		return -1;
	}

	ret = utils_create_pipe(dst);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = fcntl(dst[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl pipe cloexec");
			goto error;
		}
		/*
		 * Note: we override any flag that could have been
		 * previously set on the fd.
		 */
		ret = fcntl(dst[i], F_SETFL, O_NONBLOCK);
		if (ret < 0) {
			PERROR("fcntl pipe nonblock");
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Close both read and write side of the pipe.
 */
LTTNG_HIDDEN
void utils_close_pipe(int *src)
{
	int i, ret;

	if (src == NULL) {
		return;
	}

	for (i = 0; i < 2; i++) {
		/* Safety check */
		if (src[i] < 0) {
			continue;
		}

		ret = close(src[i]);
		if (ret) {
			PERROR("close pipe");
		}
	}
}

/*
 * Create a new string using two strings range.
 */
LTTNG_HIDDEN
char *utils_strdupdelim(const char *begin, const char *end)
{
	char *str;

	str = zmalloc(end - begin + 1);
	if (str == NULL) {
		PERROR("zmalloc strdupdelim");
		goto error;
	}

	memcpy(str, begin, end - begin);
	str[end - begin] = '\0';

error:
	return str;
}

/*
 * Set CLOEXEC flag to the give file descriptor.
 */
LTTNG_HIDDEN
int utils_set_fd_cloexec(int fd)
{
	int ret;

	if (fd < 0) {
		ret = -EINVAL;
		goto end;
	}

	ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl cloexec");
		ret = -errno;
	}

end:
	return ret;
}

/*
 * Create pid file to the given path and filename.
 */
LTTNG_HIDDEN
int utils_create_pid_file(pid_t pid, const char *filepath)
{
	int ret;
	FILE *fp;

	assert(filepath);

	fp = fopen(filepath, "w");
	if (fp == NULL) {
		PERROR("open pid file %s", filepath);
		ret = -1;
		goto error;
	}

	ret = fprintf(fp, "%d\n", (int) pid);
	if (ret < 0) {
		PERROR("fprintf pid file");
		goto error;
	}

	if (fclose(fp)) {
		PERROR("fclose");
	}
	DBG("Pid %d written in file %s", (int) pid, filepath);
	ret = 0;
error:
	return ret;
}

/*
 * Create lock file to the given path and filename.
 * Returns the associated file descriptor, -1 on error.
 */
LTTNG_HIDDEN
int utils_create_lock_file(const char *filepath)
{
	int ret;
	int fd;
	struct flock lock;

	assert(filepath);

	memset(&lock, 0, sizeof(lock));
	fd = open(filepath, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR |
		S_IRGRP | S_IWGRP);
	if (fd < 0) {
		PERROR("open lock file %s", filepath);
		fd = -1;
		goto error;
	}

	/*
	 * Attempt to lock the file. If this fails, there is
	 * already a process using the same lock file running
	 * and we should exit.
	 */
	lock.l_whence = SEEK_SET;
	lock.l_type = F_WRLCK;

	ret = fcntl(fd, F_SETLK, &lock);
	if (ret == -1) {
		PERROR("fcntl lock file");
		ERR("Could not get lock file %s, another instance is running.",
			filepath);
		if (close(fd)) {
			PERROR("close lock file");
		}
		fd = ret;
		goto error;
	}

error:
	return fd;
}

/*
 * On some filesystems (e.g. nfs), mkdir will validate access rights before
 * checking for the existence of the path element. This means that on a setup
 * where "/home/" is a mounted NFS share, and running as an unpriviledged user,
 * recursively creating a path of the form "/home/my_user/trace/" will fail with
 * EACCES on mkdir("/home", ...).
 *
 * Performing a stat(...) on the path to check for existence allows us to
 * work around this behaviour.
 */
static
int mkdir_check_exists(const char *path, mode_t mode)
{
	int ret = 0;
	struct stat st;

	ret = stat(path, &st);
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
	ret = mkdir(path, mode);
end:
	return ret;
}

/*
 * Create directory using the given path and mode.
 *
 * On success, return 0 else a negative error code.
 */
LTTNG_HIDDEN
int utils_mkdir(const char *path, mode_t mode, int uid, int gid)
{
	int ret;

	if (uid < 0 || gid < 0) {
		ret = mkdir_check_exists(path, mode);
	} else {
		ret = run_as_mkdir(path, mode, uid, gid);
	}
	if (ret < 0) {
		if (errno != EEXIST) {
			PERROR("mkdir %s, uid %d, gid %d", path ? path : "NULL",
					uid, gid);
		} else {
			ret = 0;
		}
	}

	return ret;
}

/*
 * Internal version of mkdir_recursive. Runs as the current user.
 * Don't call directly; use utils_mkdir_recursive().
 *
 * This function is ominously marked as "unsafe" since it should only
 * be called by a caller that has transitioned to the uid and gid under which
 * the directory creation should occur.
 */
LTTNG_HIDDEN
int _utils_mkdir_recursive_unsafe(const char *path, mode_t mode)
{
	char *p, tmp[PATH_MAX];
	size_t len;
	int ret;

	assert(path);

	ret = snprintf(tmp, sizeof(tmp), "%s", path);
	if (ret < 0) {
		PERROR("snprintf mkdir");
		goto error;
	}

	len = ret;
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
			ret = mkdir_check_exists(tmp, mode);
			if (ret < 0) {
				if (errno != EACCES) {
					PERROR("mkdir recursive");
					ret = -errno;
					goto error;
				}
			}
			*p = '/';
		}
	}

	ret = mkdir_check_exists(tmp, mode);
	if (ret < 0) {
		PERROR("mkdir recursive last element");
		ret = -errno;
	}

error:
	return ret;
}

/*
 * Recursively create directory using the given path and mode, under the
 * provided uid and gid.
 *
 * On success, return 0 else a negative error code.
 */
LTTNG_HIDDEN
int utils_mkdir_recursive(const char *path, mode_t mode, int uid, int gid)
{
	int ret;

	if (uid < 0 || gid < 0) {
		/* Run as current user. */
		ret = _utils_mkdir_recursive_unsafe(path, mode);
	} else {
		ret = run_as_mkdir_recursive(path, mode, uid, gid);
	}
	if (ret < 0) {
		PERROR("mkdir %s, uid %d, gid %d", path ? path : "NULL",
				uid, gid);
	}

	return ret;
}

/*
 * path is the output parameter. It needs to be PATH_MAX len.
 *
 * Return 0 on success or else a negative value.
 */
static int utils_stream_file_name(char *path,
		const char *path_name, const char *file_name,
		uint64_t size, uint64_t count,
		const char *suffix)
{
	int ret;
	char full_path[PATH_MAX];
	char *path_name_suffix = NULL;
	char *extra = NULL;

	ret = snprintf(full_path, sizeof(full_path), "%s/%s",
			path_name, file_name);
	if (ret < 0) {
		PERROR("snprintf create output file");
		goto error;
	}

	/* Setup extra string if suffix or/and a count is needed. */
	if (size > 0 && suffix) {
		ret = asprintf(&extra, "_%" PRIu64 "%s", count, suffix);
	} else if (size > 0) {
		ret = asprintf(&extra, "_%" PRIu64, count);
	} else if (suffix) {
		ret = asprintf(&extra, "%s", suffix);
	}
	if (ret < 0) {
		PERROR("Allocating extra string to name");
		goto error;
	}

	/*
	 * If we split the trace in multiple files, we have to add the count at
	 * the end of the tracefile name.
	 */
	if (extra) {
		ret = asprintf(&path_name_suffix, "%s%s", full_path, extra);
		if (ret < 0) {
			PERROR("Allocating path name with extra string");
			goto error_free_suffix;
		}
		strncpy(path, path_name_suffix, PATH_MAX - 1);
		path[PATH_MAX - 1] = '\0';
	} else {
		strncpy(path, full_path, PATH_MAX - 1);
	}
	path[PATH_MAX - 1] = '\0';
	ret = 0;

	free(path_name_suffix);
error_free_suffix:
	free(extra);
error:
	return ret;
}

/*
 * Create the stream file on disk.
 *
 * Return 0 on success or else a negative value.
 */
LTTNG_HIDDEN
int utils_create_stream_file(const char *path_name, char *file_name, uint64_t size,
		uint64_t count, int uid, int gid, char *suffix)
{
	int ret, flags, mode;
	char path[PATH_MAX];

	ret = utils_stream_file_name(path, path_name, file_name,
			size, count, suffix);
	if (ret < 0) {
		goto error;
	}

	flags = O_WRONLY | O_CREAT | O_TRUNC;
	/* Open with 660 mode */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	if (uid < 0 || gid < 0) {
		ret = open(path, flags, mode);
	} else {
		ret = run_as_open(path, flags, mode, uid, gid);
	}
	if (ret < 0) {
		PERROR("open stream path %s", path);
	}
error:
	return ret;
}

/*
 * Unlink the stream tracefile from disk.
 *
 * Return 0 on success or else a negative value.
 */
LTTNG_HIDDEN
int utils_unlink_stream_file(const char *path_name, char *file_name, uint64_t size,
		uint64_t count, int uid, int gid, char *suffix)
{
	int ret;
	char path[PATH_MAX];

	ret = utils_stream_file_name(path, path_name, file_name,
			size, count, suffix);
	if (ret < 0) {
		goto error;
	}
	if (uid < 0 || gid < 0) {
		ret = unlink(path);
	} else {
		ret = run_as_unlink(path, uid, gid);
	}
	if (ret < 0) {
		goto error;
	}
error:
	DBG("utils_unlink_stream_file %s returns %d", path, ret);
	return ret;
}

/*
 * Change the output tracefile according to the given size and count The
 * new_count pointer is set during this operation.
 *
 * From the consumer, the stream lock MUST be held before calling this function
 * because we are modifying the stream status.
 *
 * Return 0 on success or else a negative value.
 */
LTTNG_HIDDEN
int utils_rotate_stream_file(char *path_name, char *file_name, uint64_t size,
		uint64_t count, int uid, int gid, int out_fd, uint64_t *new_count,
		int *stream_fd)
{
	int ret;

	assert(stream_fd);

	ret = close(out_fd);
	if (ret < 0) {
		PERROR("Closing tracefile");
		goto error;
	}
	*stream_fd = -1;

	if (count > 0) {
		/*
		 * In tracefile rotation, for the relay daemon we need
		 * to unlink the old file if present, because it may
		 * still be open in reading by the live thread, and we
		 * need to ensure that we do not overwrite the content
		 * between get_index and get_packet. Since we have no
		 * way to verify integrity of the data content compared
		 * to the associated index, we need to ensure the reader
		 * has exclusive access to the file content, and that
		 * the open of the data file is performed in get_index.
		 * Unlinking the old file rather than overwriting it
		 * achieves this.
		 */
		if (new_count) {
			*new_count = (*new_count + 1) % count;
		}
		ret = utils_unlink_stream_file(path_name, file_name, size,
				new_count ? *new_count : 0, uid, gid, 0);
		if (ret < 0 && errno != ENOENT) {
			goto error;
		}
	} else {
		if (new_count) {
			(*new_count)++;
		}
	}

	ret = utils_create_stream_file(path_name, file_name, size,
			new_count ? *new_count : 0, uid, gid, 0);
	if (ret < 0) {
		goto error;
	}
	*stream_fd = ret;

	/* Success. */
	ret = 0;

error:
	return ret;
}


/**
 * Parse a string that represents a size in human readable format. It
 * supports decimal integers suffixed by 'k', 'K', 'M' or 'G'.
 *
 * The suffix multiply the integer by:
 * 'k': 1024
 * 'M': 1024^2
 * 'G': 1024^3
 *
 * @param str	The string to parse.
 * @param size	Pointer to a uint64_t that will be filled with the
 *		resulting size.
 *
 * @return 0 on success, -1 on failure.
 */
LTTNG_HIDDEN
int utils_parse_size_suffix(const char * const str, uint64_t * const size)
{
	int ret;
	uint64_t base_size;
	long shift = 0;
	const char *str_end;
	char *num_end;

	if (!str) {
		DBG("utils_parse_size_suffix: received a NULL string.");
		ret = -1;
		goto end;
	}

	/* strtoull will accept a negative number, but we don't want to. */
	if (strchr(str, '-') != NULL) {
		DBG("utils_parse_size_suffix: invalid size string, should not contain '-'.");
		ret = -1;
		goto end;
	}

	/* str_end will point to the \0 */
	str_end = str + strlen(str);
	errno = 0;
	base_size = strtoull(str, &num_end, 0);
	if (errno != 0) {
		PERROR("utils_parse_size_suffix strtoull");
		ret = -1;
		goto end;
	}

	if (num_end == str) {
		/* strtoull parsed nothing, not good. */
		DBG("utils_parse_size_suffix: strtoull had nothing good to parse.");
		ret = -1;
		goto end;
	}

	/* Check if a prefix is present. */
	switch (*num_end) {
	case 'G':
		shift = GIBI_LOG2;
		num_end++;
		break;
	case 'M': /*  */
		shift = MEBI_LOG2;
		num_end++;
		break;
	case 'K':
	case 'k':
		shift = KIBI_LOG2;
		num_end++;
		break;
	case '\0':
		break;
	default:
		DBG("utils_parse_size_suffix: invalid suffix.");
		ret = -1;
		goto end;
	}

	/* Check for garbage after the valid input. */
	if (num_end != str_end) {
		DBG("utils_parse_size_suffix: Garbage after size string.");
		ret = -1;
		goto end;
	}

	*size = base_size << shift;

	/* Check for overflow */
	if ((*size >> shift) != base_size) {
		DBG("utils_parse_size_suffix: oops, overflow detected.");
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	return ret;
}

/*
 * fls: returns the position of the most significant bit.
 * Returns 0 if no bit is set, else returns the position of the most
 * significant bit (from 1 to 32 on 32-bit, from 1 to 64 on 64-bit).
 */
#if defined(__i386) || defined(__x86_64)
static inline unsigned int fls_u32(uint32_t x)
{
	int r;

	asm("bsrl %1,%0\n\t"
		"jnz 1f\n\t"
		"movl $-1,%0\n\t"
		"1:\n\t"
		: "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U32
#endif

#if defined(__x86_64)
static inline
unsigned int fls_u64(uint64_t x)
{
	long r;

	asm("bsrq %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movq $-1,%0\n\t"
	    "1:\n\t"
	    : "=r" (r) : "rm" (x));
	return r + 1;
}
#define HAS_FLS_U64
#endif

#ifndef HAS_FLS_U64
static __attribute__((unused))
unsigned int fls_u64(uint64_t x)
{
	unsigned int r = 64;

	if (!x)
		return 0;

	if (!(x & 0xFFFFFFFF00000000ULL)) {
		x <<= 32;
		r -= 32;
	}
	if (!(x & 0xFFFF000000000000ULL)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF00000000000000ULL)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF000000000000000ULL)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC000000000000000ULL)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x8000000000000000ULL)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif

#ifndef HAS_FLS_U32
static __attribute__((unused)) unsigned int fls_u32(uint32_t x)
{
	unsigned int r = 32;

	if (!x) {
		return 0;
	}
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}
#endif

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
LTTNG_HIDDEN
int utils_get_count_order_u32(uint32_t x)
{
	if (!x) {
		return -1;
	}

	return fls_u32(x - 1);
}

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
LTTNG_HIDDEN
int utils_get_count_order_u64(uint64_t x)
{
	if (!x) {
		return -1;
	}

	return fls_u64(x - 1);
}

/**
 * Obtain the value of LTTNG_HOME environment variable, if exists.
 * Otherwise returns the value of HOME.
 */
LTTNG_HIDDEN
char *utils_get_home_dir(void)
{
	char *val = NULL;
	struct passwd *pwd;

	val = lttng_secure_getenv(DEFAULT_LTTNG_HOME_ENV_VAR);
	if (val != NULL) {
		goto end;
	}
	val = lttng_secure_getenv(DEFAULT_LTTNG_FALLBACK_HOME_ENV_VAR);
	if (val != NULL) {
		goto end;
	}

	/* Fallback on the password file entry. */
	pwd = getpwuid(getuid());
	if (!pwd) {
		goto end;
	}
	val = pwd->pw_dir;

	DBG3("Home directory is '%s'", val);

end:
	return val;
}

/**
 * Get user's home directory. Dynamically allocated, must be freed
 * by the caller.
 */
LTTNG_HIDDEN
char *utils_get_user_home_dir(uid_t uid)
{
	struct passwd pwd;
	struct passwd *result;
	char *home_dir = NULL;
	char *buf = NULL;
	long buflen;
	int ret;

	buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buflen == -1) {
		goto end;
	}
retry:
	buf = zmalloc(buflen);
	if (!buf) {
		goto end;
	}

	ret = getpwuid_r(uid, &pwd, buf, buflen, &result);
	if (ret || !result) {
		if (ret == ERANGE) {
			free(buf);
			buflen *= 2;
			goto retry;
		}
		goto end;
	}

	home_dir = strdup(pwd.pw_dir);
end:
	free(buf);
	return home_dir;
}

/*
 * With the given format, fill dst with the time of len maximum siz.
 *
 * Return amount of bytes set in the buffer or else 0 on error.
 */
LTTNG_HIDDEN
size_t utils_get_current_time_str(const char *format, char *dst, size_t len)
{
	size_t ret;
	time_t rawtime;
	struct tm *timeinfo;

	assert(format);
	assert(dst);

	/* Get date and time for session path */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	ret = strftime(dst, len, format, timeinfo);
	if (ret == 0) {
		ERR("Unable to strftime with format %s at dst %p of len %zu", format,
				dst, len);
	}

	return ret;
}

/*
 * Return the group ID matching name, else 0 if it cannot be found.
 */
LTTNG_HIDDEN
gid_t utils_get_group_id(const char *name)
{
	struct group *grp;

	grp = getgrnam(name);
	if (!grp) {
		static volatile int warn_once;

		if (!warn_once) {
			WARN("No tracing group detected");
			warn_once = 1;
		}
		return 0;
	}
	return grp->gr_gid;
}

/*
 * Return a newly allocated option string. This string is to be used as the
 * optstring argument of getopt_long(), see GETOPT(3). opt_count is the number
 * of elements in the long_options array. Returns NULL if the string's
 * allocation fails.
 */
LTTNG_HIDDEN
char *utils_generate_optstring(const struct option *long_options,
		size_t opt_count)
{
	int i;
	size_t string_len = opt_count, str_pos = 0;
	char *optstring;

	/*
	 * Compute the necessary string length. One letter per option, two when an
	 * argument is necessary, and a trailing NULL.
	 */
	for (i = 0; i < opt_count; i++) {
		string_len += long_options[i].has_arg ? 1 : 0;
	}

	optstring = zmalloc(string_len);
	if (!optstring) {
		goto end;
	}

	for (i = 0; i < opt_count; i++) {
		if (!long_options[i].name) {
			/* Got to the trailing NULL element */
			break;
		}

		if (long_options[i].val != '\0') {
			optstring[str_pos++] = (char) long_options[i].val;
			if (long_options[i].has_arg) {
				optstring[str_pos++] = ':';
			}
		}
	}

end:
	return optstring;
}

/*
 * Try to remove a hierarchy of empty directories, recursively. Don't unlink
 * any file. Try to rmdir any empty directory within the hierarchy.
 */
LTTNG_HIDDEN
int utils_recursive_rmdir(const char *path)
{
	DIR *dir;
	size_t path_len;
	int dir_fd, ret = 0, closeret, is_empty = 1;
	struct dirent *entry;

	/* Open directory */
	dir = opendir(path);
	if (!dir) {
		PERROR("Cannot open '%s' path", path);
		return -1;
	}
	dir_fd = lttng_dirfd(dir);
	if (dir_fd < 0) {
		PERROR("lttng_dirfd");
		return -1;
	}

	path_len = strlen(path);
	while ((entry = readdir(dir))) {
		struct stat st;
		size_t name_len;
		char filename[PATH_MAX];

		if (!strcmp(entry->d_name, ".")
				|| !strcmp(entry->d_name, "..")) {
			continue;
		}

		name_len = strlen(entry->d_name);
		if (path_len + name_len + 2 > sizeof(filename)) {
			ERR("Failed to remove file: path name too long (%s/%s)",
				path, entry->d_name);
			continue;
		}
		if (snprintf(filename, sizeof(filename), "%s/%s",
				path, entry->d_name) < 0) {
			ERR("Failed to format path.");
			continue;
		}

		if (stat(filename, &st)) {
			PERROR("stat");
			continue;
		}

		if (S_ISDIR(st.st_mode)) {
			char subpath[PATH_MAX];

			strncpy(subpath, path, PATH_MAX);
			subpath[PATH_MAX - 1] = '\0';
			strncat(subpath, "/",
				PATH_MAX - strlen(subpath) - 1);
			strncat(subpath, entry->d_name,
				PATH_MAX - strlen(subpath) - 1);
			if (utils_recursive_rmdir(subpath)) {
				is_empty = 0;
			}
		} else if (S_ISREG(st.st_mode)) {
			is_empty = 0;
		} else {
			ret = -EINVAL;
			goto end;
		}
	}
end:
	closeret = closedir(dir);
	if (closeret) {
		PERROR("closedir");
	}
	if (is_empty) {
		DBG3("Attempting rmdir %s", path);
		ret = rmdir(path);
	}
	return ret;
}

LTTNG_HIDDEN
int utils_truncate_stream_file(int fd, off_t length)
{
	int ret;

	ret = ftruncate(fd, length);
	if (ret < 0) {
		PERROR("ftruncate");
		goto end;
	}
	ret = lseek(fd, length, SEEK_SET);
	if (ret < 0) {
		PERROR("lseek");
		goto end;
	}
end:
	return ret;
}

static const char *get_man_bin_path(void)
{
	char *env_man_path = lttng_secure_getenv(DEFAULT_MAN_BIN_PATH_ENV);

	if (env_man_path) {
		return env_man_path;
	}

	return DEFAULT_MAN_BIN_PATH;
}

LTTNG_HIDDEN
int utils_show_help(int section, const char *page_name,
		const char *help_msg)
{
	char section_string[8];
	const char *man_bin_path = get_man_bin_path();
	int ret = 0;

	if (help_msg) {
		printf("%s", help_msg);
		goto end;
	}

	/* Section integer -> section string */
	ret = sprintf(section_string, "%d", section);
	assert(ret > 0 && ret < 8);

	/*
	 * Execute man pager.
	 *
	 * We provide -M to man here because LTTng-tools can
	 * be installed outside /usr, in which case its man pages are
	 * not located in the default /usr/share/man directory.
	 */
	ret = execlp(man_bin_path, "man", "-M", MANPATH,
		section_string, page_name, NULL);

end:
	return ret;
}
