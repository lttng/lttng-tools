/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
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

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <regex.h>

#include <common/common.h>
#include <common/runas.h>

#include "utils.h"
#include "defaults.h"

/*
 * Return the realpath(3) of the path even if the last directory token does not
 * exist. For example, with /tmp/test1/test2, if test2/ does not exist but the
 * /tmp/test1 does, the real path is returned. In normal time, realpath(3)
 * fails if the end point directory does not exist.
 */
LTTNG_HIDDEN
char *utils_expand_path(const char *path)
{
	const char *end_path = path;
	char *next, *cut_path = NULL, *expanded_path = NULL;

	/* Safety net */
	if (path == NULL) {
		goto error;
	}

	/* Find last token delimited by '/' */
	while ((next = strpbrk(end_path + 1, "/"))) {
		end_path = next;
	}

	/* Cut last token from original path */
	cut_path = strndup(path, end_path - path);

	expanded_path = zmalloc(PATH_MAX);
	if (expanded_path == NULL) {
		PERROR("zmalloc expand path");
		goto error;
	}

	expanded_path = realpath((char *)cut_path, expanded_path);
	if (expanded_path == NULL) {
		switch (errno) {
		case ENOENT:
			ERR("%s: No such file or directory", cut_path);
			break;
		default:
			PERROR("realpath utils expand path");
			break;
		}
		goto error;
	}

	/* Add end part to expanded path */
	strncat(expanded_path, end_path, PATH_MAX - strlen(expanded_path) - 1);

	free(cut_path);
	return expanded_path;

error:
	free(expanded_path);
	free(cut_path);
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

	ret = fprintf(fp, "%d\n", pid);
	if (ret < 0) {
		PERROR("fprintf pid file");
	}

	fclose(fp);
	DBG("Pid %d written in file %s", pid, filepath);
error:
	return ret;
}

/*
 * Recursively create directory using the given path and mode.
 *
 * On success, return 0 else a negative error code.
 */
LTTNG_HIDDEN
int utils_mkdir_recursive(const char *path, mode_t mode)
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
			ret = mkdir(tmp, mode);
			if (ret < 0) {
				if (errno != EEXIST) {
					PERROR("mkdir recursive");
					ret = -errno;
					goto error;
				}
			}
			*p = '/';
		}
	}

	ret = mkdir(tmp, mode);
	if (ret < 0) {
		if (errno != EEXIST) {
			PERROR("mkdir recursive last piece");
			ret = -errno;
		} else {
			ret = 0;
		}
	}

error:
	return ret;
}

/*
 * Create the stream tracefile on disk.
 *
 * Return 0 on success or else a negative value.
 */
LTTNG_HIDDEN
int utils_create_stream_file(const char *path_name, char *file_name, uint64_t size,
		uint64_t count, int uid, int gid)
{
	int ret, out_fd, flags, mode;
	char full_path[PATH_MAX], *path_name_id = NULL, *path;

	assert(path_name);
	assert(file_name);

	ret = snprintf(full_path, sizeof(full_path), "%s/%s",
			path_name, file_name);
	if (ret < 0) {
		PERROR("snprintf create output file");
		goto error;
	}

	/*
	 * If we split the trace in multiple files, we have to add the count at the
	 * end of the tracefile name
	 */
	if (size > 0) {
		ret = asprintf(&path_name_id, "%s_%" PRIu64, full_path, count);
		if (ret < 0) {
			PERROR("Allocating path name ID");
			goto error;
		}
		path = path_name_id;
	} else {
		path = full_path;
	}

	flags = O_WRONLY | O_CREAT | O_TRUNC;
	/* Open with 660 mode */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	if (uid < 0 || gid < 0) {
		out_fd = open(path, flags, mode);
	} else {
		out_fd = run_as_open(path, flags, mode, uid, gid);
	}
	if (out_fd < 0) {
		PERROR("open stream path %s", path);
		goto error_open;
	}
	ret = out_fd;

error_open:
	free(path_name_id);
error:
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
		uint64_t count, int uid, int gid, int out_fd, uint64_t *new_count)
{
	int ret;

	ret = close(out_fd);
	if (ret < 0) {
		PERROR("Closing tracefile");
		goto error;
	}

	if (count > 0) {
		*new_count = (*new_count + 1) % count;
	} else {
		(*new_count)++;
	}

	return utils_create_stream_file(path_name, file_name, size, *new_count,
			uid, gid);
error:
	return ret;
}

/**
 * Prints the error message corresponding to a regex error code.
 *
 * @param errcode	The error code.
 * @param regex		The regex object that produced the error code.
 */
static void regex_print_error(int errcode, regex_t *regex)
{
	/* Get length of error message and allocate accordingly */
	size_t length;
	char *buffer;

	assert(regex != NULL);

	length = regerror(errcode, regex, NULL, 0);
	if (length == 0) {
		ERR("regerror returned a length of 0");
		return;
	}

	buffer = zmalloc(length);
	if (!buffer) {
		ERR("regex_print_error: zmalloc failed");
		return;
	}

	/* Get and print error message */
	regerror(errcode, regex, buffer, length);
	ERR("regex error: %s\n", buffer);
	free(buffer);

}

/**
 * Parse a string that represents a size in human readable format. It
 * supports decimal integers suffixed by 'k', 'M' or 'G'.
 *
 * The suffix multiply the integer by:
 * 'k': 1024
 * 'M': 1024^2
 * 'G': 1024^3
 *
 * @param str	The string to parse.
 * @param size	Pointer to a size_t that will be filled with the
 *		resulting size.
 *
 * @return 0 on success, -1 on failure.
 */
int utils_parse_size_suffix(char *str, uint64_t *size)
{
	regex_t regex;
	int ret;
	const int nmatch = 3;
	regmatch_t suffix_match, matches[nmatch];
	unsigned long long base_size;
	long shift = 0;

	if (!str) {
		return 0;
	}

	/* Compile regex */
	ret = regcomp(&regex, "^\\(0x\\)\\{0,1\\}[0-9][0-9]*\\([kKMG]\\{0,1\\}\\)$", 0);
	if (ret != 0) {
		regex_print_error(ret, &regex);
		ret = -1;
		goto end;
	}

	/* Match regex */
	ret = regexec(&regex, str, nmatch, matches, 0);
	if (ret != 0) {
		ret = -1;
		goto free;
	}

	/* There is a match ! */
	errno = 0;
	base_size = strtoull(str, NULL, 0);
	if (errno != 0) {
		PERROR("strtoull");
		ret = -1;
		goto free;
	}

	/* Check if there is a suffix */
	suffix_match = matches[2];
	if (suffix_match.rm_eo - suffix_match.rm_so == 1) {
		switch (*(str + suffix_match.rm_so)) {
		case 'K':
		case 'k':
			shift = KIBI_LOG2;
			break;
		case 'M':
			shift = MEBI_LOG2;
			break;
		case 'G':
			shift = GIBI_LOG2;
			break;
		default:
			ERR("parse_human_size: invalid suffix");
			ret = -1;
			goto free;
		}
	}

	*size = base_size << shift;

	/* Check for overflow */
	if ((*size >> shift) != base_size) {
		ERR("parse_size_suffix: oops, overflow detected.");
		ret = -1;
		goto free;
	}

	ret = 0;

free:
	regfree(&regex);
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

/**
 * Obtain the value of LTTNG_HOME environment variable, if exists.
 * Otherwise returns the value of HOME.
 */
char *utils_get_home_dir(void)
{
	char *val = NULL;
	val = getenv(DEFAULT_LTTNG_HOME_ENV_VAR);
	if (val != NULL) {
		return val;
	}
	return getenv(DEFAULT_LTTNG_FALLBACK_HOME_ENV_VAR);
}
