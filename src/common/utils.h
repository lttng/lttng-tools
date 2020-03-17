/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _COMMON_UTILS_H
#define _COMMON_UTILS_H

#include <getopt.h>
#include <lttng/lttng-error.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/compat/directory-handle.h>

#define KIBI_LOG2 10
#define MEBI_LOG2 20
#define GIBI_LOG2 30

char *utils_partial_realpath(const char *path, char *resolved_path,
		size_t size);
char *utils_expand_path(const char *path);
char *utils_expand_path_keep_symlink(const char *path);
int utils_create_pipe(int *dst);
int utils_create_pipe_cloexec(int *dst);
int utils_create_pipe_cloexec_nonblock(int *dst);
void utils_close_pipe(int *src);
char *utils_strdupdelim(const char *begin, const char *end);
int utils_set_fd_cloexec(int fd);
int utils_create_pid_file(pid_t pid, const char *filepath);
int utils_mkdir(const char *path, mode_t mode, int uid, int gid);
int utils_mkdir_recursive(const char *path, mode_t mode, int uid, int gid);
int utils_stream_file_path(const char *path_name, const char *file_name,
		uint64_t size, uint64_t count, const char *suffix,
		char *out_stream_path, size_t stream_path_len);
int utils_parse_size_suffix(char const * const str, uint64_t * const size);
int utils_parse_time_suffix(char const * const str, uint64_t * const time_us);
int utils_get_count_order_u32(uint32_t x);
int utils_get_count_order_u64(uint64_t x);
const char *utils_get_home_dir(void);
char *utils_get_user_home_dir(uid_t uid);
size_t utils_get_current_time_str(const char *format, char *dst, size_t len);
int utils_get_group_id(const char *name, bool warn, gid_t *gid);
char *utils_generate_optstring(const struct option *long_options,
		size_t opt_count);
int utils_create_lock_file(const char *filepath);
int utils_recursive_rmdir(const char *path);
int utils_truncate_stream_file(int fd, off_t length);
int utils_show_help(int section, const char *page_name, const char *help_msg);
int utils_get_memory_available(size_t *value);
int utils_get_memory_total(size_t *value);
int utils_change_working_directory(const char *path);
enum lttng_error_code utils_user_id_from_name(
		const char *user_name, uid_t *user_id);
enum lttng_error_code utils_group_id_from_name(
		const char *group_name, gid_t *group_id);

#endif /* _COMMON_UTILS_H */
