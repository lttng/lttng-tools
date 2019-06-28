#ifndef _RUNAS_H
#define _RUNAS_H

/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/macros.h>

/*
 * The run-as process is launched by forking without an exec*() call. This means
 * that any resource allocated before the run-as worker is launched should be
 * cleaned-up after the fork(). This callback allows the user to perform this
 * clean-up.
 *
 * Note that the callback will _not_ be invoked if the LTTNG_DEBUG_NOCLONE
 * environment variable is set as the clean-up is not needed (and may not be
 * expected).
 *
 * A negative return value will cause the run-as process to exit with a non-zero
 * value.
 */
typedef int (*post_fork_cleanup_cb)(void *user_data);

LTTNG_HIDDEN
int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_mkdirat_recursive(int dirfd, const char *path, mode_t mode,
		uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_mkdirat(int dirfd, const char *path, mode_t mode,
		uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_open(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_openat(int dirfd, const char *filename, int flags, mode_t mode,
		uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_unlink(const char *path, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_unlinkat(int dirfd, const char *filename, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_rmdir(const char *path, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_rmdir_recursive(const char *path, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_rmdirat(int dirfd, const char *path, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_rmdirat_recursive(int dirfd, const char *path, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_rename(const char *old, const char *new, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_renameat(int old_dirfd, const char *old,
		int new_dirfd, const char *new, uid_t uid, gid_t gid);
LTTNG_HIDDEN
int run_as_extract_elf_symbol_offset(int fd, const char* function,
		uid_t uid, gid_t gid, uint64_t *offset);
LTTNG_HIDDEN
int run_as_extract_sdt_probe_offsets(int fd, const char *provider_name,
		const char* probe_name, uid_t uid, gid_t gid,
		uint64_t **offsets, uint32_t *num_offset);
LTTNG_HIDDEN
int run_as_create_worker(const char *procname,
		post_fork_cleanup_cb clean_up_func, void *clean_up_user_data);
LTTNG_HIDDEN
void run_as_destroy_worker(void);

#endif /* _RUNAS_H */
