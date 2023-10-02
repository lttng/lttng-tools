/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "defaults.hpp"
#include "time.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/compat/directory-handle.hpp>
#include <common/compat/dirent.hpp>
#include <common/compat/getenv.hpp>
#include <common/compat/string.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/readwrite.hpp>
#include <common/runas.hpp>
#include <common/string-utils/format.hpp>

#include <lttng/constant.h>

#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PROC_MEMINFO_PATH	       "/proc/meminfo"
#define PROC_MEMINFO_MEMAVAILABLE_LINE "MemAvailable:"
#define PROC_MEMINFO_MEMTOTAL_LINE     "MemTotal:"

/* The lnullptrh of the longest field of `/proc/meminfo`. */
#define PROC_MEMINFO_FIELD_MAX_NAME_LEN 20

#if (PROC_MEMINFO_FIELD_MAX_NAME_LEN == 20)
#define MAX_NAME_LEN_SCANF_IS_A_BROKEN_API "19"
#else
#error MAX_NAME_LEN_SCANF_IS_A_BROKEN_API must be updated to match (PROC_MEMINFO_FIELD_MAX_NAME_LEN - 1)
#endif

#define FALLBACK_USER_BUFLEN  16384
#define FALLBACK_GROUP_BUFLEN 16384

/*
 * Create a pipe in dst.
 */
int utils_create_pipe(int *dst)
{
	int ret;

	if (dst == nullptr) {
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
int utils_create_pipe_cloexec(int *dst)
{
	int ret, i;

	if (dst == nullptr) {
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
int utils_create_pipe_cloexec_nonblock(int *dst)
{
	int ret, i;

	if (dst == nullptr) {
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
void utils_close_pipe(int *src)
{
	int i, ret;

	if (src == nullptr) {
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
		src[i] = -1;
	}
}

/*
 * Create a new string using two strings range.
 */
char *utils_strdupdelim(const char *begin, const char *end)
{
	char *str = zmalloc<char>(end - begin + 1);

	if (str == nullptr) {
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
int utils_create_pid_file(pid_t pid, const char *filepath)
{
	int ret, fd = -1;
	FILE *fp = nullptr;

	LTTNG_ASSERT(filepath);

	fd = open(filepath, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		PERROR("open file %s", filepath);
		ret = -1;
		goto error;
	}

	fp = fdopen(fd, "w");
	if (fp == nullptr) {
		PERROR("fdopen file %s", filepath);
		ret = -1;
		if (close(fd)) {
			PERROR("Failed to close `%s` file descriptor while handling fdopen error",
			       filepath);
		}

		goto error;
	}

	ret = fprintf(fp, "%d\n", (int) pid);
	if (ret < 0) {
		PERROR("fprintf file %s", filepath);
		ret = -1;
		goto error;
	}

	DBG("'%d' written in file %s", (int) pid, filepath);
	ret = 0;

error:
	if (fp && fclose(fp)) {
		PERROR("fclose file %s", filepath);
	}
	return ret;
}

/*
 * Create lock file to the given path and filename.
 * Returns the associated file descriptor, -1 on error.
 */
int utils_create_lock_file(const char *filepath)
{
	int ret;
	int fd;
	struct flock lock;

	LTTNG_ASSERT(filepath);

	memset(&lock, 0, sizeof(lock));
	fd = open(filepath, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
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
		ERR("Could not get lock file %s, another instance is running.", filepath);
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
 * Create directory using the given path and mode.
 *
 * On success, return 0 else a negative error code.
 */
int utils_mkdir(const char *path, mode_t mode, int uid, int gid)
{
	int ret;
	struct lttng_directory_handle *handle;
	const struct lttng_credentials creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE((uid_t) uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE((gid_t) gid),
	};

	handle = lttng_directory_handle_create(nullptr);
	if (!handle) {
		ret = -1;
		goto end;
	}
	ret = lttng_directory_handle_create_subdirectory_as_user(
		handle, path, mode, (uid >= 0 || gid >= 0) ? &creds : nullptr);
end:
	lttng_directory_handle_put(handle);
	return ret;
}

/*
 * Recursively create directory using the given path and mode, under the
 * provided uid and gid.
 *
 * On success, return 0 else a negative error code.
 */
int utils_mkdir_recursive(const char *path, mode_t mode, int uid, int gid)
{
	int ret;
	struct lttng_directory_handle *handle;
	const struct lttng_credentials creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE((uid_t) uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE((gid_t) gid),
	};

	handle = lttng_directory_handle_create(nullptr);
	if (!handle) {
		ret = -1;
		goto end;
	}
	ret = lttng_directory_handle_create_subdirectory_recursive_as_user(
		handle, path, mode, (uid >= 0 || gid >= 0) ? &creds : nullptr);
end:
	lttng_directory_handle_put(handle);
	return ret;
}

/*
 * out_stream_path is the output parameter.
 *
 * Return 0 on success or else a negative value.
 */
int utils_stream_file_path(const char *path_name,
			   const char *file_name,
			   uint64_t size,
			   uint64_t count,
			   const char *suffix,
			   char *out_stream_path,
			   size_t stream_path_len)
{
	int ret;
	char count_str[MAX_INT_DEC_LEN(count) + 1] = {};
	const char *path_separator;

	if (path_name && (path_name[0] == '\0' || path_name[strlen(path_name) - 1] == '/')) {
		path_separator = "";
	} else {
		path_separator = "/";
	}

	path_name = path_name ?: "";
	suffix = suffix ?: "";
	if (size > 0) {
		ret = snprintf(count_str, sizeof(count_str), "_%" PRIu64, count);
		LTTNG_ASSERT(ret > 0 && ret < sizeof(count_str));
	}

	ret = snprintf(out_stream_path,
		       stream_path_len,
		       "%s%s%s%s%s",
		       path_name,
		       path_separator,
		       file_name,
		       count_str,
		       suffix);
	if (ret < 0 || ret >= stream_path_len) {
		ERR("Truncation occurred while formatting stream path");
		ret = -1;
	} else {
		ret = 0;
	}
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
int utils_parse_size_suffix(const char *const str, uint64_t *const size)
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
	if (strchr(str, '-') != nullptr) {
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

/**
 * Parse a string that represents a time in human readable format. It
 * supports decimal integers suffixed by:
 *     "us" for microsecond,
 *     "ms" for millisecond,
 *     "s"  for second,
 *     "m"  for minute,
 *     "h"  for hour
 *
 * The suffix multiply the integer by:
 *     "us" : 1
 *     "ms" : 1000
 *     "s"  : 1000000
 *     "m"  : 60000000
 *     "h"  : 3600000000
 *
 * Note that unit-less numbers are assumed to be microseconds.
 *
 * @param str		The string to parse, assumed to be NULL-terminated.
 * @param time_us	Pointer to a uint64_t that will be filled with the
 *			resulting time in microseconds.
 *
 * @return 0 on success, -1 on failure.
 */
int utils_parse_time_suffix(char const *const str, uint64_t *const time_us)
{
	int ret;
	uint64_t base_time;
	uint64_t multiplier = 1;
	const char *str_end;
	char *num_end;

	if (!str) {
		DBG("utils_parse_time_suffix: received a NULL string.");
		ret = -1;
		goto end;
	}

	/* strtoull will accept a negative number, but we don't want to. */
	if (strchr(str, '-') != nullptr) {
		DBG("utils_parse_time_suffix: invalid time string, should not contain '-'.");
		ret = -1;
		goto end;
	}

	/* str_end will point to the \0 */
	str_end = str + strlen(str);
	errno = 0;
	base_time = strtoull(str, &num_end, 10);
	if (errno != 0) {
		PERROR("utils_parse_time_suffix strtoull on string \"%s\"", str);
		ret = -1;
		goto end;
	}

	if (num_end == str) {
		/* strtoull parsed nothing, not good. */
		DBG("utils_parse_time_suffix: strtoull had nothing good to parse.");
		ret = -1;
		goto end;
	}

	/* Check if a prefix is present. */
	switch (*num_end) {
	case 'u':
		/*
		 * Microsecond (us)
		 *
		 * Skip the "us" if the string matches the "us" suffix,
		 * otherwise let the check for the end of the string handle
		 * the error reporting.
		 */
		if (*(num_end + 1) == 's') {
			num_end += 2;
		}
		break;
	case 'm':
		if (*(num_end + 1) == 's') {
			/* Millisecond (ms) */
			multiplier = USEC_PER_MSEC;
			/* Skip the 's' */
			num_end++;
		} else {
			/* Minute (m) */
			multiplier = USEC_PER_MINUTE;
		}
		num_end++;
		break;
	case 's':
		/* Second */
		multiplier = USEC_PER_SEC;
		num_end++;
		break;
	case 'h':
		/* Hour */
		multiplier = USEC_PER_HOURS;
		num_end++;
		break;
	case '\0':
		break;
	default:
		DBG("utils_parse_time_suffix: invalid suffix.");
		ret = -1;
		goto end;
	}

	/* Check for garbage after the valid input. */
	if (num_end != str_end) {
		DBG("utils_parse_time_suffix: Garbage after time string.");
		ret = -1;
		goto end;
	}

	*time_us = base_time * multiplier;

	/* Check for overflow */
	if ((*time_us / multiplier) != base_time) {
		DBG("utils_parse_time_suffix: oops, overflow detected.");
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
	    : "=r"(r)
	    : "rm"(x));
	return r + 1;
}
#define HAS_FLS_U32
#endif

#if defined(__x86_64) && defined(__LP64__)
static inline unsigned int fls_u64(uint64_t x)
{
	long r;

	asm("bsrq %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movq $-1,%0\n\t"
	    "1:\n\t"
	    : "=r"(r)
	    : "rm"(x));
	return r + 1;
}
#define HAS_FLS_U64
#endif

#ifndef HAS_FLS_U64
static __attribute__((unused)) unsigned int fls_u64(uint64_t x)
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
const char *utils_get_home_dir()
{
	char *val = nullptr;
	struct passwd *pwd;

	val = lttng_secure_getenv(DEFAULT_LTTNG_HOME_ENV_VAR);
	if (val != nullptr) {
		goto end;
	}
	val = lttng_secure_getenv(DEFAULT_LTTNG_FALLBACK_HOME_ENV_VAR);
	if (val != nullptr) {
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
char *utils_get_user_home_dir(uid_t uid)
{
	struct passwd pwd;
	struct passwd *result;
	char *home_dir = nullptr;
	char *buf = nullptr;
	long buflen;
	int ret;

	buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buflen == -1) {
		goto end;
	}
retry:
	buf = zmalloc<char>(buflen);
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
size_t utils_get_current_time_str(const char *format, char *dst, size_t len)
{
	size_t ret;
	time_t rawtime;
	struct tm *timeinfo;

	LTTNG_ASSERT(format);
	LTTNG_ASSERT(dst);

	/* Get date and time for session path */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_FORMAT_NONLITERAL
	ret = strftime(dst, len, format, timeinfo);
	DIAGNOSTIC_POP
	if (ret == 0) {
		ERR("Unable to strftime with format %s at dst %p of len %zu", format, dst, len);
	}

	return ret;
}

/*
 * Return 0 on success and set *gid to the group_ID matching the passed name.
 * Else -1 if it cannot be found or an error occurred.
 */
int utils_get_group_id(const char *name, bool warn, gid_t *gid)
{
	static volatile int warn_once;
	int ret;
	long sys_len;
	size_t len;
	struct group grp;
	struct group *result;
	struct lttng_dynamic_buffer buffer;

	/* Get the system limit, if it exists. */
	sys_len = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (sys_len == -1) {
		len = 1024;
	} else {
		len = (size_t) sys_len;
	}

	lttng_dynamic_buffer_init(&buffer);
	ret = lttng_dynamic_buffer_set_size(&buffer, len);
	if (ret) {
		ERR("Failed to allocate group info buffer");
		ret = -1;
		goto error;
	}

	while ((ret = getgrnam_r(name, &grp, buffer.data, buffer.size, &result)) == ERANGE) {
		const size_t new_len = 2 * buffer.size;

		/* Buffer is not big enough, increase its size. */
		if (new_len < buffer.size) {
			ERR("Group info buffer size overflow");
			ret = -1;
			goto error;
		}

		ret = lttng_dynamic_buffer_set_size(&buffer, new_len);
		if (ret) {
			ERR("Failed to grow group info buffer to %zu bytes", new_len);
			ret = -1;
			goto error;
		}
	}
	if (ret) {
		if (ret == ESRCH) {
			DBG("Could not find group file entry for group name '%s'", name);
		} else {
			PERROR("Failed to get group file entry for group name '%s'", name);
		}

		ret = -1;
		goto error;
	}

	/* Group not found. */
	if (!result) {
		ret = -1;
		goto error;
	}

	*gid = result->gr_gid;
	ret = 0;

error:
	if (ret && warn && !warn_once) {
		WARN("No tracing group detected");
		warn_once = 1;
	}
	lttng_dynamic_buffer_reset(&buffer);
	return ret;
}

/*
 * Return a newly allocated option string. This string is to be used as the
 * optstring argument of getopt_long(), see GETOPT(3). opt_count is the number
 * of elements in the long_options array. Returns NULL if the string's
 * allocation fails.
 */
char *utils_generate_optstring(const struct option *long_options, size_t opt_count)
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

	optstring = zmalloc<char>(string_len);
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
int utils_recursive_rmdir(const char *path)
{
	int ret;
	struct lttng_directory_handle *handle;

	handle = lttng_directory_handle_create(nullptr);
	if (!handle) {
		ret = -1;
		goto end;
	}
	ret = lttng_directory_handle_remove_subdirectory(handle, path);
end:
	lttng_directory_handle_put(handle);
	return ret;
}

int utils_truncate_stream_file(int fd, off_t length)
{
	int ret;
	off_t lseek_ret;

	ret = ftruncate(fd, length);
	if (ret < 0) {
		PERROR("ftruncate");
		goto end;
	}
	lseek_ret = lseek(fd, length, SEEK_SET);
	if (lseek_ret < 0) {
		PERROR("lseek");
		ret = -1;
		goto end;
	}
end:
	return ret;
}

static const char *get_man_bin_path()
{
	char *env_man_path = lttng_secure_getenv(DEFAULT_MAN_BIN_PATH_ENV);

	if (env_man_path) {
		return env_man_path;
	}

	return DEFAULT_MAN_BIN_PATH;
}

static const char *get_manpath()
{
	char *manpath = lttng_secure_getenv(DEFAULT_MANPATH);

	if (manpath) {
		return manpath;
	}

	/* As defined during configuration. */
	return MANPATH;
}

int utils_show_help(int section, const char *page_name, const char *help_msg)
{
	char section_string[8];
	const char *man_bin_path = get_man_bin_path();
	const char *manpath = get_manpath();
	int ret = 0;

	if (help_msg) {
		printf("%s", help_msg);
		goto end;
	}

	/* Section integer -> section string */
	ret = snprintf(section_string, sizeof(section_string), "%d", section);
	LTTNG_ASSERT(ret > 0 && ret < 8);

	/*
	 * Execute man pager.
	 *
	 * We provide -M to man here because LTTng-tools can
	 * be installed outside /usr, in which case its man pages are
	 * not located in the default /usr/share/man directory.
	 */
	ret = execlp(man_bin_path, "man", "-M", manpath, section_string, page_name, NULL);

end:
	return ret;
}

static int read_proc_meminfo_field(const char *field, uint64_t *value)
{
	int ret;
	FILE *proc_meminfo;
	char name[PROC_MEMINFO_FIELD_MAX_NAME_LEN] = {};

	proc_meminfo = fopen(PROC_MEMINFO_PATH, "r");
	if (!proc_meminfo) {
		PERROR("Failed to fopen() " PROC_MEMINFO_PATH);
		ret = -1;
		goto fopen_error;
	}

	/*
	 * Read the contents of /proc/meminfo line by line to find the right
	 * field.
	 */
	while (!feof(proc_meminfo)) {
		uint64_t value_kb;

		ret = fscanf(proc_meminfo,
			     "%" MAX_NAME_LEN_SCANF_IS_A_BROKEN_API "s %" SCNu64 " kB\n",
			     name,
			     &value_kb);
		if (ret == EOF) {
			/*
			 * fscanf() returning EOF can indicate EOF or an error.
			 */
			if (ferror(proc_meminfo)) {
				PERROR("Failed to parse " PROC_MEMINFO_PATH);
			}
			break;
		}

		if (ret == 2 && strcmp(name, field) == 0) {
			/*
			 * This number is displayed in kilo-bytes. Return the
			 * number of bytes.
			 */
			if (value_kb > UINT64_MAX / 1024) {
				ERR("Overflow on kb to bytes conversion");
				break;
			}

			*value = value_kb * 1024;
			ret = 0;
			goto found;
		}
	}
	/* Reached the end of the file without finding the right field. */
	ret = -1;

found:
	fclose(proc_meminfo);
fopen_error:
	return ret;
}

/*
 * Returns an estimate of the number of bytes of memory available based on the
 * the information in `/proc/meminfo`. The number returned by this function is
 * a best guess.
 */
int utils_get_memory_available(uint64_t *value)
{
	return read_proc_meminfo_field(PROC_MEMINFO_MEMAVAILABLE_LINE, value);
}

/*
 * Returns the total size of the memory on the system in bytes based on the
 * the information in `/proc/meminfo`.
 */
int utils_get_memory_total(uint64_t *value)
{
	return read_proc_meminfo_field(PROC_MEMINFO_MEMTOTAL_LINE, value);
}

int utils_change_working_directory(const char *path)
{
	int ret;

	LTTNG_ASSERT(path);

	DBG("Changing working directory to \"%s\"", path);
	ret = chdir(path);
	if (ret) {
		PERROR("Failed to change working directory to \"%s\"", path);
		goto end;
	}

	/* Check for write access */
	if (access(path, W_OK)) {
		if (errno == EACCES) {
			/*
			 * Do not treat this as an error since the permission
			 * might change in the lifetime of the process
			 */
			DBG("Working directory \"%s\" is not writable", path);
		} else {
			PERROR("Failed to check if working directory \"%s\" is writable", path);
		}
	}

end:
	return ret;
}

enum lttng_error_code utils_user_id_from_name(const char *user_name, uid_t *uid)
{
	struct passwd p, *pres;
	int ret;
	enum lttng_error_code ret_val = LTTNG_OK;
	char *buf = nullptr;
	ssize_t buflen;

	buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buflen < 0) {
		buflen = FALLBACK_USER_BUFLEN;
	}

	buf = zmalloc<char>(buflen);
	if (!buf) {
		ret_val = LTTNG_ERR_NOMEM;
		goto end;
	}

	for (;;) {
		ret = getpwnam_r(user_name, &p, buf, buflen, &pres);
		switch (ret) {
		case EINTR:
			continue;
		case ERANGE:
			buflen *= 2;
			free(buf);
			buf = zmalloc<char>(buflen);
			if (!buf) {
				ret_val = LTTNG_ERR_NOMEM;
				goto end;
			}
			continue;
		default:
			goto end_loop;
		}
	}
end_loop:

	switch (ret) {
	case 0:
		if (pres == nullptr) {
			ret_val = LTTNG_ERR_USER_NOT_FOUND;
		} else {
			*uid = p.pw_uid;
			DBG("Lookup of tracker UID/VUID: name '%s' maps to uid %" PRId64,
			    user_name,
			    (int64_t) *uid);
			ret_val = LTTNG_OK;
		}
		break;
	case ENOENT:
	case ESRCH:
	case EBADF:
	case EPERM:
		ret_val = LTTNG_ERR_USER_NOT_FOUND;
		break;
	default:
		ret_val = LTTNG_ERR_NOMEM;
	}
end:
	free(buf);
	return ret_val;
}

enum lttng_error_code utils_group_id_from_name(const char *group_name, gid_t *gid)
{
	struct group g, *gres;
	int ret;
	enum lttng_error_code ret_val = LTTNG_OK;
	char *buf = nullptr;
	ssize_t buflen;

	buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (buflen < 0) {
		buflen = FALLBACK_GROUP_BUFLEN;
	}

	buf = zmalloc<char>(buflen);
	if (!buf) {
		ret_val = LTTNG_ERR_NOMEM;
		goto end;
	}

	for (;;) {
		ret = getgrnam_r(group_name, &g, buf, buflen, &gres);
		switch (ret) {
		case EINTR:
			continue;
		case ERANGE:
			buflen *= 2;
			free(buf);
			buf = zmalloc<char>(buflen);
			if (!buf) {
				ret_val = LTTNG_ERR_NOMEM;
				goto end;
			}
			continue;
		default:
			goto end_loop;
		}
	}
end_loop:

	switch (ret) {
	case 0:
		if (gres == nullptr) {
			ret_val = LTTNG_ERR_GROUP_NOT_FOUND;
		} else {
			*gid = g.gr_gid;
			DBG("Lookup of tracker GID/GUID: name '%s' maps to gid %" PRId64,
			    group_name,
			    (int64_t) *gid);
			ret_val = LTTNG_OK;
		}
		break;
	case ENOENT:
	case ESRCH:
	case EBADF:
	case EPERM:
		ret_val = LTTNG_ERR_GROUP_NOT_FOUND;
		break;
	default:
		ret_val = LTTNG_ERR_NOMEM;
	}
end:
	free(buf);
	return ret_val;
}

int utils_parse_unsigned_long_long(const char *str, unsigned long long *value)
{
	int ret;
	char *endptr;

	LTTNG_ASSERT(str);
	LTTNG_ASSERT(value);

	errno = 0;
	*value = strtoull(str, &endptr, 10);

	/* Conversion failed. Out of range? */
	if (errno != 0) {
		/* Don't print an error; allow the caller to log a better error. */
		DBG("Failed to parse string as unsigned long long number: string = '%s', errno = %d",
		    str,
		    errno);
		ret = -1;
		goto end;
	}

	/* Not the end of the string or empty string. */
	if (*endptr || endptr == str) {
		DBG("Failed to parse string as unsigned long long number: string = '%s'", str);
		ret = -1;
		goto end;
	}

	ret = 0;

end:
	return ret;
}
