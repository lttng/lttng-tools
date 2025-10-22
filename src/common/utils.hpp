/*
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _COMMON_UTILS_H
#define _COMMON_UTILS_H

#include <common/compat/directory-handle.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/lttng-error.h>

#include <fstream>
#include <getopt.h>
#include <iostream>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define KIBI_LOG2 10
#define MEBI_LOG2 20
#define GIBI_LOG2 30

int utils_create_pipe(int *dst);
int utils_create_pipe_cloexec(int *dst);
int utils_create_pipe_cloexec_nonblock(int *dst);
void utils_close_pipe(int *src);
char *utils_strdupdelim(const char *begin, const char *end);
int utils_set_fd_cloexec(int fd);
int utils_create_pid_file(pid_t pid, const char *filepath);
int utils_mkdir(const char *path, mode_t mode, int uid, int gid);
int utils_mkdir_recursive(const char *path, mode_t mode, int uid, int gid);
int utils_stream_file_path(const char *path_name,
			   const char *file_name,
			   uint64_t size,
			   uint64_t count,
			   const char *suffix,
			   char *out_stream_path,
			   size_t stream_path_len);
int utils_parse_size_suffix(const char *const str, uint64_t *const size);
int utils_parse_time_suffix(const char *const str, uint64_t *const time_us);
int utils_get_count_order_u32(uint32_t x);
int utils_get_count_order_u64(uint64_t x);
char *utils_get_rundir(gid_t tracing_group);
const char *utils_get_home_dir();
char *utils_get_user_home_dir(uid_t uid);
char *utils_get_lttng_ust_ctl_path_override_dir();

size_t utils_get_current_time_str(const char *format, char *dst, size_t len)
	ATTR_FORMAT_STRFTIME(1);

int utils_get_group_id(const char *name, bool warn, gid_t *gid);
char *utils_generate_optstring(const struct option *long_options, size_t opt_count);
int utils_recursive_rmdir(const char *path);
int utils_truncate_stream_file(int fd, off_t length);
int utils_show_help(int section, const char *page_name, const char *help_msg);
int utils_get_memory_available(uint64_t *value);
int utils_get_memory_total(uint64_t *value);
int utils_change_working_directory(const char *path);
enum lttng_error_code utils_user_id_from_name(const char *user_name, uid_t *user_id);
enum lttng_error_code utils_group_id_from_name(const char *group_name, gid_t *group_id);
unsigned int utils_get_cpu_count() LTTNG_MAY_THROW;
enum lttng_error_code utils_check_enough_available_memory(uint64_t num_bytes,
							  uint64_t *bytes_available);

/*
 * Parse `str` as an unsigned long long value.
 *
 * Return 0 on success.  Return -1 on failure which can be because:
 *
 * - `str` is zero length
 * - `str` contains invalid
 */
int utils_parse_unsigned_long_long(const char *str, unsigned long long *value);

/*
 * Write a value to the given path and filename.
 *
 * Returns 0 on success and -1 on failure.
 */
template <typename ValueType>
int utils_create_value_file(const ValueType value, const lttng::c_string_view filepath)
{
	DBG_FMT("Creating value file: path=`{}`, value={}", filepath, value);
	try {
		std::ofstream file;
		const auto tmp_filepath = std::string(filepath.data()) + ".tmp";

		file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
		/* Open the temporary file with truncation to create or overwrite it. */
		file.open(tmp_filepath, std::ios::out | std::ios::trunc);
		file << value << std::endl;
		file.close();

		/* Rename the temporary file to the final filepath. */
		if (rename(tmp_filepath.c_str(), filepath.data()) != 0) {
			ERR_FMT("Failed to rename temporary file: temp_path=`{}`, final_path=`{}`, error=`{}`",
				tmp_filepath,
				filepath,
				strerror(errno));
			return -1;
		}
	} catch (const std::exception& e) {
		ERR_FMT("Failed to produce value file: path=`{}`, value={}, error=`{}`",
			filepath,
			value,
			e.what());
		return -1;
	}

	return 0;
}

bool utils_force_experimental_ctf_2();
std::vector<int> list_open_fds();
std::pair<double, const char *> utils_value_unit_from_size(std::uint64_t bytes);
std::string utils_string_from_size(std::uint64_t bytes);

#endif /* _COMMON_UTILS_H */
