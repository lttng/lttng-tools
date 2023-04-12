#ifndef _RUNAS_H
#define _RUNAS_H

/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/macros.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

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
using post_fork_cleanup_cb = int (*)(void *);

int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid);
int run_as_mkdirat_recursive(int dirfd, const char *path, mode_t mode, uid_t uid, gid_t gid);
int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid);
int run_as_mkdirat(int dirfd, const char *path, mode_t mode, uid_t uid, gid_t gid);
int run_as_open(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid);
int run_as_openat(int dirfd, const char *filename, int flags, mode_t mode, uid_t uid, gid_t gid);
int run_as_unlink(const char *path, uid_t uid, gid_t gid);
int run_as_unlinkat(int dirfd, const char *filename, uid_t uid, gid_t gid);
int run_as_rmdir(const char *path, uid_t uid, gid_t gid);
int run_as_rmdir_recursive(const char *path, uid_t uid, gid_t gid, int flags);
int run_as_rmdirat(int dirfd, const char *path, uid_t uid, gid_t gid);
int run_as_rmdirat_recursive(int dirfd, const char *path, uid_t uid, gid_t gid, int flags);
int run_as_rename(const char *old_name, const char *new_name, uid_t uid, gid_t gid);
int run_as_renameat(int old_dirfd,
		    const char *old_name,
		    int new_dirfd,
		    const char *new_name,
		    uid_t uid,
		    gid_t gid);
int run_as_extract_elf_symbol_offset(
	int fd, const char *function, uid_t uid, gid_t gid, uint64_t *offset);
int run_as_extract_sdt_probe_offsets(int fd,
				     const char *provider_name,
				     const char *probe_name,
				     uid_t uid,
				     gid_t gid,
				     uint64_t **offsets,
				     uint32_t *num_offset);
int run_as_generate_filter_bytecode(const char *filter_expression,
				    const struct lttng_credentials *creds,
				    struct lttng_bytecode **bytecode);
int run_as_create_worker(const char *procname,
			 post_fork_cleanup_cb clean_up_func,
			 void *clean_up_user_data);
void run_as_destroy_worker();

#endif /* _RUNAS_H */
