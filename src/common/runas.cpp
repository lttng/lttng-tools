/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "runas.hpp"

#include <common/bytecode/bytecode.hpp>
#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/compat/getenv.hpp>
#include <common/compat/string.hpp>
#include <common/defaults.hpp>
#include <common/filter/filter-ast.hpp>
#include <common/lttng-elf.hpp>
#include <common/lttng-kernel.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/thread.hpp>
#include <common/unix.hpp>
#include <common/utils.hpp>

#include <lttng/constant.h>

#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GETPW_BUFFER_FALLBACK_SIZE 4096

enum run_as_cmd {
	RUN_AS_MKDIR,
	RUN_AS_MKDIRAT,
	RUN_AS_MKDIR_RECURSIVE,
	RUN_AS_MKDIRAT_RECURSIVE,
	RUN_AS_OPEN,
	RUN_AS_OPENAT,
	RUN_AS_UNLINK,
	RUN_AS_UNLINKAT,
	RUN_AS_RMDIR,
	RUN_AS_RMDIRAT,
	RUN_AS_RMDIR_RECURSIVE,
	RUN_AS_RMDIRAT_RECURSIVE,
	RUN_AS_RENAME,
	RUN_AS_RENAMEAT,
	RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET,
	RUN_AS_EXTRACT_SDT_PROBE_OFFSETS,
	RUN_AS_GENERATE_FILTER_BYTECODE,
};

namespace {
struct run_as_data;
struct run_as_ret;
using run_as_fct = int (*)(struct run_as_data *, struct run_as_ret *);

struct run_as_mkdir_data {
	int dirfd;
	char path[LTTNG_PATH_MAX];
	mode_t mode;
} LTTNG_PACKED;

struct run_as_open_data {
	int dirfd;
	char path[LTTNG_PATH_MAX];
	int flags;
	mode_t mode;
} LTTNG_PACKED;

struct run_as_unlink_data {
	int dirfd;
	char path[LTTNG_PATH_MAX];
} LTTNG_PACKED;

struct run_as_rmdir_data {
	int dirfd;
	char path[LTTNG_PATH_MAX];
	int flags; /* enum lttng_directory_handle_rmdir_recursive_flags. */
} LTTNG_PACKED;

struct run_as_extract_elf_symbol_offset_data {
	int fd;
	char function[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

struct run_as_extract_sdt_probe_offsets_data {
	int fd;
	char probe_name[LTTNG_SYMBOL_NAME_LEN];
	char provider_name[LTTNG_SYMBOL_NAME_LEN];
} LTTNG_PACKED;

struct run_as_generate_filter_bytecode_data {
	char filter_expression[LTTNG_FILTER_MAX_LEN];
} LTTNG_PACKED;

struct run_as_rename_data {
	/*
	 * [0] = old_dirfd
	 * [1] = new_dirfd
	 */
	int dirfds[2];
	char old_path[LTTNG_PATH_MAX];
	char new_path[LTTNG_PATH_MAX];
} LTTNG_PACKED;

struct run_as_open_ret {
	int fd;
} LTTNG_PACKED;

struct run_as_extract_elf_symbol_offset_ret {
	uint64_t offset;
} LTTNG_PACKED;

struct run_as_extract_sdt_probe_offsets_ret {
	uint32_t num_offset;
	uint64_t offsets[LTTNG_KERNEL_ABI_MAX_UPROBE_NUM];
} LTTNG_PACKED;

struct run_as_generate_filter_bytecode_ret {
	/* A lttng_bytecode_filter struct with 'dynamic' payload. */
	char bytecode[LTTNG_FILTER_MAX_LEN];
} LTTNG_PACKED;

struct run_as_data {
	enum run_as_cmd cmd;
	union {
		struct run_as_mkdir_data mkdir;
		struct run_as_open_data open;
		struct run_as_unlink_data unlink;
		struct run_as_rmdir_data rmdir;
		struct run_as_rename_data rename;
		struct run_as_extract_elf_symbol_offset_data extract_elf_symbol_offset;
		struct run_as_extract_sdt_probe_offsets_data extract_sdt_probe_offsets;
		struct run_as_generate_filter_bytecode_data generate_filter_bytecode;
	} u;
	uid_t uid;
	gid_t gid;
} LTTNG_PACKED;

/*
 * The run_as_ret structure holds the returned value and status of the command.
 *
 * The `u` union field holds the return value of the command; in most cases it
 * represents the success or the failure of the command. In more complex
 * commands, it holds a computed value.
 *
 * The _errno field is the errno recorded after the execution of the command.
 *
 * The _error fields is used the signify that return status of the command. For
 * simple commands returning `int` the _error field will be the same as the
 * ret_int field. In complex commands, it signify the success or failure of the
 * command.
 *
 */
struct run_as_ret {
	union {
		int ret;
		struct run_as_open_ret open;
		struct run_as_extract_elf_symbol_offset_ret extract_elf_symbol_offset;
		struct run_as_extract_sdt_probe_offsets_ret extract_sdt_probe_offsets;
		struct run_as_generate_filter_bytecode_ret generate_filter_bytecode;
	} u;
	int _errno;
	bool _error;
} LTTNG_PACKED;

#define COMMAND_IN_FDS(data_ptr)                                                           \
	({                                                                                 \
		int *fds = NULL;                                                           \
		if (command_properties[(data_ptr)->cmd].in_fds_offset != -1) {             \
			fds = (int *) ((char *) (data_ptr) +                               \
				       command_properties[(data_ptr)->cmd].in_fds_offset); \
		}                                                                          \
		fds;                                                                       \
	})

#define COMMAND_OUT_FDS(cmd, ret_ptr)                                           \
	({                                                                      \
		int *fds = NULL;                                                \
		if (command_properties[cmd].out_fds_offset != -1) {             \
			fds = (int *) ((char *) (ret_ptr) +                     \
				       command_properties[cmd].out_fds_offset); \
		}                                                               \
		fds;                                                            \
	})

#define COMMAND_IN_FD_COUNT(data_ptr) ({ command_properties[(data_ptr)->cmd].in_fd_count; })

#define COMMAND_OUT_FD_COUNT(cmd) ({ command_properties[cmd].out_fd_count; })

#define COMMAND_USE_CWD_FD(data_ptr) command_properties[(data_ptr)->cmd].use_cwd_fd

struct run_as_command_properties {
	/* Set to -1 when not applicable. */
	ptrdiff_t in_fds_offset, out_fds_offset;
	unsigned int in_fd_count, out_fd_count;
	bool use_cwd_fd;
};

const struct run_as_command_properties command_properties[] = {
	{
		.in_fds_offset = offsetof(struct run_as_data, u.mkdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = true,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.mkdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.mkdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = true,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.mkdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.open.dirfd),
		.out_fds_offset = offsetof(struct run_as_ret, u.open.fd),
		.in_fd_count = 1,
		.out_fd_count = 1,
		.use_cwd_fd = true,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.open.dirfd),
		.out_fds_offset = offsetof(struct run_as_ret, u.open.fd),
		.in_fd_count = 1,
		.out_fd_count = 1,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.unlink.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = true,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.unlink.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.rmdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = true,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.rmdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.rmdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = true,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.rmdir.dirfd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.rename.dirfds),
		.out_fds_offset = -1,
		.in_fd_count = 2,
		.out_fd_count = 0,
		.use_cwd_fd = true,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.rename.dirfds),
		.out_fds_offset = -1,
		.in_fd_count = 2,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.extract_elf_symbol_offset.fd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = offsetof(struct run_as_data, u.extract_sdt_probe_offsets.fd),
		.out_fds_offset = -1,
		.in_fd_count = 1,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
	{
		.in_fds_offset = -1,
		.out_fds_offset = -1,
		.in_fd_count = 0,
		.out_fd_count = 0,
		.use_cwd_fd = false,
	},
};

struct run_as_worker_data {
	pid_t pid; /* Worker PID. */
	int sockpair[2];
	char *procname;
};

/* Single global worker per process (for now). */
run_as_worker_data *global_worker;
/* Lock protecting the worker. */
pthread_mutex_t worker_lock = PTHREAD_MUTEX_INITIALIZER;
} /* namespace */

#ifdef VALGRIND
static int use_clone(void)
{
	return 0;
}
#else
static int use_clone()
{
	return !lttng_secure_getenv("LTTNG_DEBUG_NOCLONE");
}
#endif

/*
 * Create recursively directory using the FULL path.
 */
static int _mkdirat_recursive(struct run_as_data *data, struct run_as_ret *ret_value)
{
	const char *path;
	mode_t mode;
	struct lttng_directory_handle *handle;

	path = data->u.mkdir.path;
	mode = data->u.mkdir.mode;

	handle = lttng_directory_handle_create_from_dirfd(data->u.mkdir.dirfd);
	if (!handle) {
		ret_value->_errno = errno;
		ret_value->_error = true;
		ret_value->u.ret = -1;
		goto end;
	}
	/* Ownership of dirfd is transferred to the handle. */
	data->u.mkdir.dirfd = -1;
	/* Safe to call as we have transitioned to the requested uid/gid. */
	ret_value->u.ret = lttng_directory_handle_create_subdirectory_recursive(handle, path, mode);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret) != 0;
	lttng_directory_handle_put(handle);
end:
	return ret_value->u.ret;
}

static int _mkdirat(struct run_as_data *data, struct run_as_ret *ret_value)
{
	const char *path;
	mode_t mode;
	struct lttng_directory_handle *handle;

	path = data->u.mkdir.path;
	mode = data->u.mkdir.mode;

	handle = lttng_directory_handle_create_from_dirfd(data->u.mkdir.dirfd);
	if (!handle) {
		ret_value->u.ret = -1;
		ret_value->_errno = errno;
		ret_value->_error = true;
		goto end;
	}
	/* Ownership of dirfd is transferred to the handle. */
	data->u.mkdir.dirfd = -1;
	/* Safe to call as we have transitioned to the requested uid/gid. */
	ret_value->u.ret = lttng_directory_handle_create_subdirectory(handle, path, mode);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret) != 0;
	lttng_directory_handle_put(handle);
end:
	return ret_value->u.ret;
}

static int _open(struct run_as_data *data, struct run_as_ret *ret_value)
{
	int fd;
	struct lttng_directory_handle *handle;

	handle = lttng_directory_handle_create_from_dirfd(data->u.open.dirfd);
	if (!handle) {
		ret_value->_errno = errno;
		ret_value->_error = true;
		ret_value->u.ret = -1;
		goto end;
	}
	/* Ownership of dirfd is transferred to the handle. */
	data->u.open.dirfd = -1;

	fd = lttng_directory_handle_open_file(
		handle, data->u.open.path, data->u.open.flags, data->u.open.mode);
	if (fd < 0) {
		ret_value->u.ret = -1;
		ret_value->u.open.fd = -1;
	} else {
		ret_value->u.ret = 0;
		ret_value->u.open.fd = fd;
	}

	ret_value->_errno = errno;
	ret_value->_error = fd < 0;
	lttng_directory_handle_put(handle);
end:
	return ret_value->u.ret;
}

static int _unlink(struct run_as_data *data, struct run_as_ret *ret_value)
{
	struct lttng_directory_handle *handle;

	handle = lttng_directory_handle_create_from_dirfd(data->u.unlink.dirfd);
	if (!handle) {
		ret_value->u.ret = -1;
		ret_value->_errno = errno;
		ret_value->_error = true;
		goto end;
	}

	/* Ownership of dirfd is transferred to the handle. */
	data->u.unlink.dirfd = -1;

	ret_value->u.ret = lttng_directory_handle_unlink_file(handle, data->u.unlink.path);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret) != 0;
	lttng_directory_handle_put(handle);
end:
	return ret_value->u.ret;
}

static int _rmdir(struct run_as_data *data, struct run_as_ret *ret_value)
{
	struct lttng_directory_handle *handle;

	handle = lttng_directory_handle_create_from_dirfd(data->u.rmdir.dirfd);
	if (!handle) {
		ret_value->u.ret = -1;
		ret_value->_errno = errno;
		ret_value->_error = true;
		goto end;
	}

	/* Ownership of dirfd is transferred to the handle. */
	data->u.rmdir.dirfd = -1;

	ret_value->u.ret = lttng_directory_handle_remove_subdirectory(handle, data->u.rmdir.path);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret) != 0;
	lttng_directory_handle_put(handle);
end:
	return ret_value->u.ret;
}

static int _rmdir_recursive(struct run_as_data *data, struct run_as_ret *ret_value)
{
	struct lttng_directory_handle *handle;

	handle = lttng_directory_handle_create_from_dirfd(data->u.rmdir.dirfd);
	if (!handle) {
		ret_value->u.ret = -1;
		ret_value->_errno = errno;
		ret_value->_error = true;
		goto end;
	}

	/* Ownership of dirfd is transferred to the handle. */
	data->u.rmdir.dirfd = -1;

	ret_value->u.ret = lttng_directory_handle_remove_subdirectory_recursive(
		handle, data->u.rmdir.path, data->u.rmdir.flags);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret) != 0;
	lttng_directory_handle_put(handle);
end:
	return ret_value->u.ret;
}

static int _rename(struct run_as_data *data, struct run_as_ret *ret_value)
{
	const char *old_path, *new_path;
	struct lttng_directory_handle *old_handle = nullptr, *new_handle = nullptr;

	old_path = data->u.rename.old_path;
	new_path = data->u.rename.new_path;

	old_handle = lttng_directory_handle_create_from_dirfd(data->u.rename.dirfds[0]);
	if (!old_handle) {
		ret_value->u.ret = -1;
		goto end;
	}
	new_handle = lttng_directory_handle_create_from_dirfd(data->u.rename.dirfds[1]);
	if (!new_handle) {
		ret_value->u.ret = -1;
		goto end;
	}

	/* Ownership of dirfds are transferred to the handles. */
	data->u.rename.dirfds[0] = data->u.rename.dirfds[1] = -1;

	/* Safe to call as we have transitioned to the requested uid/gid. */
	ret_value->u.ret =
		lttng_directory_handle_rename(old_handle, old_path, new_handle, new_path);
end:
	lttng_directory_handle_put(old_handle);
	lttng_directory_handle_put(new_handle);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret) != 0;
	return ret_value->u.ret;
}

#ifdef HAVE_ELF_H
static int _extract_elf_symbol_offset(struct run_as_data *data, struct run_as_ret *ret_value)
{
	int ret = 0;
	uint64_t offset;

	ret_value->_error = false;
	ret = lttng_elf_get_symbol_offset(data->u.extract_elf_symbol_offset.fd,
					  data->u.extract_elf_symbol_offset.function,
					  &offset);
	if (ret) {
		DBG("Failed to extract ELF function offset");
		ret_value->_error = true;
	}
	ret_value->u.extract_elf_symbol_offset.offset = offset;

	return ret;
}

static int _extract_sdt_probe_offsets(struct run_as_data *data, struct run_as_ret *ret_value)
{
	int ret = 0;
	uint64_t *offsets = nullptr;
	uint32_t num_offset;

	ret_value->_error = false;

	/* On success, this call allocates the offsets paramater. */
	ret = lttng_elf_get_sdt_probe_offsets(data->u.extract_sdt_probe_offsets.fd,
					      data->u.extract_sdt_probe_offsets.provider_name,
					      data->u.extract_sdt_probe_offsets.probe_name,
					      &offsets,
					      &num_offset);

	if (ret) {
		DBG("Failed to extract SDT probe offsets");
		ret_value->_error = true;
		goto end;
	}

	if (num_offset <= 0 || num_offset > LTTNG_KERNEL_ABI_MAX_UPROBE_NUM) {
		DBG("Wrong number of probes.");
		ret = -1;
		ret_value->_error = true;
		goto free_offset;
	}

	/* Copy the content of the offsets array to the ret struct. */
	memcpy(ret_value->u.extract_sdt_probe_offsets.offsets,
	       offsets,
	       num_offset * sizeof(uint64_t));

	ret_value->u.extract_sdt_probe_offsets.num_offset = num_offset;

free_offset:
	free(offsets);
end:
	return ret;
}
#else
static int _extract_elf_symbol_offset(struct run_as_data *data __attribute__((unused)),
				      struct run_as_ret *ret_value __attribute__((unused)))
{
	ERR("Unimplemented runas command RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET");
	return -1;
}

static int _extract_sdt_probe_offsets(struct run_as_data *data __attribute__((unused)),
				      struct run_as_ret *ret_value __attribute__((unused)))
{
	ERR("Unimplemented runas command RUN_AS_EXTRACT_SDT_PROBE_OFFSETS");
	return -1;
}
#endif

static int _generate_filter_bytecode(struct run_as_data *data, struct run_as_ret *ret_value)
{
	int ret = 0;
	const char *filter_expression = nullptr;
	struct filter_parser_ctx *ctx = nullptr;

	ret_value->_error = false;

	filter_expression = data->u.generate_filter_bytecode.filter_expression;

	if (lttng_strnlen(filter_expression, LTTNG_FILTER_MAX_LEN - 1) ==
	    LTTNG_FILTER_MAX_LEN - 1) {
		ret_value->_error = true;
		ret = -1;
		goto end;
	}

	ret = filter_parser_ctx_create_from_filter_expression(filter_expression, &ctx);
	if (ret < 0) {
		ret_value->_error = true;
		ret = -1;
		goto end;
	}

	DBG("Size of bytecode generated: %u bytes.", bytecode_get_len(&ctx->bytecode->b));

	/* Copy the lttng_bytecode_filter object to the return structure. */
	memcpy(ret_value->u.generate_filter_bytecode.bytecode,
	       &ctx->bytecode->b,
	       sizeof(ctx->bytecode->b) + bytecode_get_len(&ctx->bytecode->b));

end:
	if (ctx) {
		filter_bytecode_free(ctx);
		filter_ir_free(ctx);
		filter_parser_ctx_free(ctx);
	}

	return ret;
}
static run_as_fct run_as_enum_to_fct(enum run_as_cmd cmd)
{
	switch (cmd) {
	case RUN_AS_MKDIR:
	case RUN_AS_MKDIRAT:
		return _mkdirat;
	case RUN_AS_MKDIR_RECURSIVE:
	case RUN_AS_MKDIRAT_RECURSIVE:
		return _mkdirat_recursive;
	case RUN_AS_OPEN:
	case RUN_AS_OPENAT:
		return _open;
	case RUN_AS_UNLINK:
	case RUN_AS_UNLINKAT:
		return _unlink;
	case RUN_AS_RMDIR:
	case RUN_AS_RMDIRAT:
		return _rmdir;
	case RUN_AS_RMDIR_RECURSIVE:
	case RUN_AS_RMDIRAT_RECURSIVE:
		return _rmdir_recursive;
	case RUN_AS_RENAME:
	case RUN_AS_RENAMEAT:
		return _rename;
	case RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET:
		return _extract_elf_symbol_offset;
	case RUN_AS_EXTRACT_SDT_PROBE_OFFSETS:
		return _extract_sdt_probe_offsets;
	case RUN_AS_GENERATE_FILTER_BYTECODE:
		return _generate_filter_bytecode;
	default:
		ERR("Unknown command %d", (int) cmd);
		return nullptr;
	}
}

static int do_send_fds(int sock, const int *fds, unsigned int fd_count)
{
	ssize_t len;
	unsigned int i;

	for (i = 0; i < fd_count; i++) {
		if (fds[i] < 0) {
			DBG("Attempt to send invalid file descriptor (fd = %i)", fds[i]);
			/* Return 0 as this is not a fatal error. */
			return 0;
		}
	}

	len = lttcomm_send_fds_unix_sock(sock, fds, fd_count);
	return len < 0 ? -1 : 0;
}

static int do_recv_fds(int sock, int *fds, unsigned int fd_count)
{
	int ret = 0;
	unsigned int i;
	ssize_t len;

	len = lttcomm_recv_fds_unix_sock(sock, fds, fd_count);
	if (len == 0) {
		ret = -1;
		goto end;
	} else if (len < 0) {
		PERROR("Failed to receive file descriptors from socket");
		ret = -1;
		goto end;
	}

	for (i = 0; i < fd_count; i++) {
		if (fds[i] < 0) {
			ERR("Invalid file descriptor received from worker (fd = %i)", fds[i]);
			/* Return 0 as this is not a fatal error. */
		}
	}
end:
	return ret;
}

static int send_fds_to_worker(const run_as_worker_data *worker, const struct run_as_data *data)
{
	int ret = 0;
	unsigned int i;

	if (COMMAND_USE_CWD_FD(data) || COMMAND_IN_FD_COUNT(data) == 0) {
		goto end;
	}

	for (i = 0; i < COMMAND_IN_FD_COUNT(data); i++) {
		if (COMMAND_IN_FDS(data)[i] < 0) {
			ERR("Refusing to send invalid fd to worker (fd = %i)",
			    COMMAND_IN_FDS(data)[i]);
			ret = -1;
			goto end;
		}
	}

	ret = do_send_fds(worker->sockpair[0], COMMAND_IN_FDS(data), COMMAND_IN_FD_COUNT(data));
	if (ret < 0) {
		PERROR("Failed to send file descriptor to run-as worker");
		ret = -1;
		goto end;
	}
end:
	return ret;
}

static int
send_fds_to_master(run_as_worker_data *worker, enum run_as_cmd cmd, struct run_as_ret *run_as_ret)
{
	int ret = 0;
	unsigned int i;

	if (COMMAND_OUT_FD_COUNT(cmd) == 0) {
		goto end;
	}

	ret = do_send_fds(
		worker->sockpair[1], COMMAND_OUT_FDS(cmd, run_as_ret), COMMAND_OUT_FD_COUNT(cmd));
	if (ret < 0) {
		PERROR("Failed to send file descriptor to master process");
		goto end;
	}

	for (i = 0; i < COMMAND_OUT_FD_COUNT(cmd); i++) {
		const int fd = COMMAND_OUT_FDS(cmd, run_as_ret)[i];
		if (fd >= 0) {
			const int ret_close = close(fd);

			if (ret_close < 0) {
				PERROR("Failed to close result file descriptor (fd = %i)", fd);
			}
		}
	}
end:
	return ret;
}

static int recv_fds_from_worker(const run_as_worker_data *worker,
				enum run_as_cmd cmd,
				struct run_as_ret *run_as_ret)
{
	int ret = 0;

	if (COMMAND_OUT_FD_COUNT(cmd) == 0) {
		goto end;
	}

	ret = do_recv_fds(
		worker->sockpair[0], COMMAND_OUT_FDS(cmd, run_as_ret), COMMAND_OUT_FD_COUNT(cmd));
	if (ret < 0) {
		PERROR("Failed to receive file descriptor from run-as worker");
		ret = -1;
	}
end:
	return ret;
}

static int recv_fds_from_master(run_as_worker_data *worker, struct run_as_data *data)
{
	int ret = 0;

	if (COMMAND_USE_CWD_FD(data)) {
		unsigned int i;

		for (i = 0; i < COMMAND_IN_FD_COUNT(data); i++) {
			COMMAND_IN_FDS(data)[i] = AT_FDCWD;
		}
		goto end;
	}

	if (COMMAND_IN_FD_COUNT(data) == 0) {
		goto end;
	}

	ret = do_recv_fds(worker->sockpair[1], COMMAND_IN_FDS(data), COMMAND_IN_FD_COUNT(data));
	if (ret < 0) {
		PERROR("Failed to receive file descriptors from master process");
		ret = -1;
	}
end:
	return ret;
}

static int cleanup_received_fds(struct run_as_data *data)
{
	int ret = 0, i;

	for (i = 0; i < COMMAND_IN_FD_COUNT(data); i++) {
		if (COMMAND_IN_FDS(data)[i] == -1) {
			continue;
		}
		ret = close(COMMAND_IN_FDS(data)[i]);
		if (ret) {
			PERROR("Failed to close file descriptor received fd in run-as worker");
			goto end;
		}
	}
end:
	return ret;
}

static int get_user_infos_from_uid(uid_t uid, char **username, gid_t *primary_gid)
{
	int ret;
	char *buf = nullptr;
	long raw_get_pw_buf_size;
	size_t get_pw_buf_size;
	struct passwd pwd;
	struct passwd *result = nullptr;

	/* Fetch the max size for the temporary buffer. */
	errno = 0;
	raw_get_pw_buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (raw_get_pw_buf_size < 0) {
		if (errno != 0) {
			PERROR("Failed to query _SC_GETPW_R_SIZE_MAX");
			goto error;
		}

		/* Limit is indeterminate. */
		WARN("Failed to query _SC_GETPW_R_SIZE_MAX as it is "
		     "indeterminate; falling back to default buffer size");
		raw_get_pw_buf_size = GETPW_BUFFER_FALLBACK_SIZE;
	}

	get_pw_buf_size = (size_t) raw_get_pw_buf_size;

	buf = calloc<char>(get_pw_buf_size);
	if (buf == nullptr) {
		PERROR("Failed to allocate buffer to get password file entries");
		goto error;
	}

	ret = getpwuid_r(uid, &pwd, buf, get_pw_buf_size, &result);
	if (ret < 0) {
		PERROR("Failed to get user information for user:  uid = %d", (int) uid);
		goto error;
	}

	if (result == nullptr) {
		ERR("Failed to find user information in password entries: uid = %d", (int) uid);
		ret = -1;
		goto error;
	}

	*username = strdup(result->pw_name);
	if (*username == nullptr) {
		PERROR("Failed to copy user name");
		goto error;
	}

	*primary_gid = result->pw_gid;

end:
	free(buf);
	return ret;
error:
	*username = nullptr;
	*primary_gid = -1;
	ret = -1;
	goto end;
}

static int demote_creds(uid_t prev_uid, gid_t prev_gid, uid_t new_uid, gid_t new_gid)
{
	int ret = 0;
	gid_t primary_gid;
	char *username = nullptr;

	/* Change the group id. */
	if (prev_gid != new_gid) {
		ret = setegid(new_gid);
		if (ret < 0) {
			PERROR("Failed to set effective group id: new_gid = %d", (int) new_gid);
			goto end;
		}
	}

	/* Change the user id. */
	if (prev_uid != new_uid) {
		ret = get_user_infos_from_uid(new_uid, &username, &primary_gid);
		if (ret < 0) {
			goto end;
		}

		/*
		 * Initialize the supplementary group access list.
		 *
		 * This is needed to handle cases where the supplementary groups
		 * of the user the process is demoting-to would give it access
		 * to a given file/folder, but not it's primary group.
		 *
		 * e.g
		 *   username: User1
		 *   Primary Group: User1
		 *   Secondary group: Disk, Network
		 *
		 *   mkdir inside the following directory must work since User1
		 *   is part of the Network group.
		 *
		 *   drwxrwx--- 2 root Network 4096 Jul 23 17:17 /tmp/my_folder/
		 *
		 *
		 * The order of the following initgroups and seteuid calls is
		 * important here;
		 * Only a root process or one with CAP_SETGID capability can
		 * call the the initgroups() function. We must initialize the
		 * supplementary groups before we change the effective
		 * UID to a less-privileged user.
		 */
		ret = initgroups(username, primary_gid);
		if (ret < 0) {
			PERROR("Failed to init the supplementary group access list: "
			       "username = `%s`, primary gid = %d",
			       username,
			       (int) primary_gid);
			goto end;
		}

		ret = seteuid(new_uid);
		if (ret < 0) {
			PERROR("Failed to set effective user id: new_uid = %d", (int) new_uid);
			goto end;
		}
	}
end:
	free(username);
	return ret;
}

static int promote_creds(uid_t prev_uid, gid_t prev_gid, uid_t new_uid, gid_t new_gid)
{
	int ret = 0;
	gid_t primary_gid;
	char *username = nullptr;

	/* Change the group id. */
	if (prev_gid != new_gid) {
		ret = setegid(new_gid);
		if (ret < 0) {
			PERROR("Failed to set effective group id: new_gid = %d", (int) new_gid);
			goto end;
		}
	}

	/* Change the user id. */
	if (prev_uid != new_uid) {
		ret = get_user_infos_from_uid(new_uid, &username, &primary_gid);
		if (ret < 0) {
			goto end;
		}

		/*
		 * seteuid call must be done before the initgroups call because
		 * we need to be privileged (CAP_SETGID) to call initgroups().
		 */
		ret = seteuid(new_uid);
		if (ret < 0) {
			PERROR("Failed to set effective user id: new_uid = %d", (int) new_uid);
			goto end;
		}

		/*
		 * Initialize the supplementary group access list.
		 *
		 * There is a possibility the groups we set in the following
		 * initgroups() call are not exactly the same as the ones we
		 * had when we originally demoted. This can happen if the
		 * /etc/group file is modified after the runas process is
		 * forked. This is very unlikely.
		 */
		ret = initgroups(username, primary_gid);
		if (ret < 0) {
			PERROR("Failed to init the supplementary group access "
			       "list: username = `%s`, primary gid = %d",
			       username,
			       (int) primary_gid)
			goto end;
		}
	}
end:
	free(username);
	return ret;
}

/*
 * Return < 0 on error, 0 if OK, 1 on hangup.
 */
static int handle_one_cmd(run_as_worker_data *worker)
{
	int ret = 0, promote_ret;
	struct run_as_data data = {};
	ssize_t readlen, writelen;
	struct run_as_ret sendret = {};
	run_as_fct cmd;
	const uid_t prev_ruid = getuid();
	const gid_t prev_rgid = getgid();

	/*
	 * Stage 1: Receive run_as_data struct from the master.
	 * The structure contains the command type and all the parameters needed for
	 * its execution
	 */
	readlen = lttcomm_recv_unix_sock(worker->sockpair[1], &data, sizeof(data));
	if (readlen == 0) {
		/* hang up */
		ret = 1;
		goto end;
	}
	if (readlen < sizeof(data)) {
		PERROR("lttcomm_recv_unix_sock error");
		ret = -1;
		goto end;
	}

	cmd = run_as_enum_to_fct(data.cmd);
	if (!cmd) {
		ret = -1;
		goto end;
	}

	/*
	 * Stage 2: Receive file descriptor from master.
	 * Some commands need a file descriptor as input so if it's needed we
	 * receive the fd using the Unix socket.
	 */
	ret = recv_fds_from_master(worker, &data);
	if (ret < 0) {
		PERROR("recv_fd_from_master error");
		ret = -1;
		goto end;
	}

	ret = demote_creds(prev_ruid, prev_rgid, data.uid, data.gid);
	if (ret < 0) {
		goto write_return;
	}

	/*
	 * Also set umask to 0 for mkdir executable bit.
	 */
	umask(0);

	/*
	 * Stage 3: Execute the command
	 */
	ret = (*cmd)(&data, &sendret);
	if (ret < 0) {
		DBG("Execution of command returned an error");
	}

write_return:
	ret = cleanup_received_fds(&data);
	if (ret < 0) {
		ERR("Error cleaning up FD");
		goto promote_back;
	}

	/*
	 * Stage 4: Send run_as_ret structure to the master.
	 * This structure contain the return value of the command and the errno.
	 */
	writelen = lttcomm_send_unix_sock(worker->sockpair[1], &sendret, sizeof(sendret));
	if (writelen < sizeof(sendret)) {
		PERROR("lttcomm_send_unix_sock error");
		ret = -1;
		goto promote_back;
	}

	/*
	 * Stage 5: Send resulting file descriptors to the master.
	 */
	ret = send_fds_to_master(worker, data.cmd, &sendret);
	if (ret < 0) {
		DBG("Sending FD to master returned an error");
	}

	ret = 0;

promote_back:
	/* Return to previous uid/gid. */
	promote_ret = promote_creds(data.uid, data.gid, prev_ruid, prev_rgid);
	if (promote_ret < 0) {
		ERR("Failed to promote back to the initial credentials");
	}

end:
	return ret;
}

static int run_as_worker(run_as_worker_data *worker)
{
	int ret;
	ssize_t writelen;
	struct run_as_ret sendret;
	size_t proc_orig_len;

	/*
	 * Initialize worker. Set a different process cmdline.
	 */
	proc_orig_len = strlen(worker->procname);
	memset(worker->procname, 0, proc_orig_len);
	strncpy(worker->procname, DEFAULT_RUN_AS_WORKER_NAME, proc_orig_len);

	ret = lttng_thread_setname(DEFAULT_RUN_AS_WORKER_NAME);
	if (ret && ret != -ENOSYS) {
		/* Don't fail as this is not essential. */
		DBG("Failed to set pthread name attribute");
	}

	memset(&sendret, 0, sizeof(sendret));

	writelen = lttcomm_send_unix_sock(worker->sockpair[1], &sendret, sizeof(sendret));
	if (writelen < sizeof(sendret)) {
		PERROR("lttcomm_send_unix_sock error");
		ret = EXIT_FAILURE;
		goto end;
	}

	for (;;) {
		ret = handle_one_cmd(worker);
		if (ret < 0) {
			ret = EXIT_FAILURE;
			goto end;
		} else if (ret > 0) {
			break;
		} else {
			continue; /* Next command. */
		}
	}
	ret = EXIT_SUCCESS;
end:
	return ret;
}

static int run_as_cmd(run_as_worker_data *worker,
		      enum run_as_cmd cmd,
		      struct run_as_data *data,
		      struct run_as_ret *ret_value,
		      uid_t uid,
		      gid_t gid)
{
	int ret = 0;
	ssize_t readlen, writelen;

	/*
	 * If we are non-root, we can only deal with our own uid.
	 */
	if (geteuid() != 0) {
		if (uid != geteuid()) {
			ret = -1;
			ret_value->_errno = EPERM;
			ERR("Client (%d)/Server (%d) UID mismatch (and sessiond is not root)",
			    (int) uid,
			    (int) geteuid());
			goto end;
		}
	}

	data->cmd = cmd;
	data->uid = uid;
	data->gid = gid;

	/*
	 * Stage 1: Send the run_as_data struct to the worker process
	 */
	writelen = lttcomm_send_unix_sock(worker->sockpair[0], data, sizeof(*data));
	if (writelen < sizeof(*data)) {
		PERROR("Error writing message to run_as");
		ret = -1;
		ret_value->_errno = EIO;
		goto end;
	}

	/*
	 * Stage 2: Send file descriptor to the worker process if needed
	 */
	ret = send_fds_to_worker(worker, data);
	if (ret) {
		PERROR("do_send_fd error");
		ret = -1;
		ret_value->_errno = EIO;
		goto end;
	}

	/*
	 * Stage 3: Wait for the execution of the command
	 */

	/*
	 * Stage 4: Receive the run_as_ret struct containing the return value and
	 * errno
	 */
	readlen = lttcomm_recv_unix_sock(worker->sockpair[0], ret_value, sizeof(*ret_value));
	if (!readlen) {
		ERR("Run-as worker has hung-up during run_as_cmd");
		ret = -1;
		ret_value->_errno = EIO;
		goto end;
	} else if (readlen < sizeof(*ret_value)) {
		PERROR("Error reading response from run_as");
		ret = -1;
		ret_value->_errno = errno;
		goto end;
	}

	if (ret_value->_error) {
		/* Skip stage 5 on error as there will be no fd to receive. */
		goto end;
	}

	/*
	 * Stage 5: Receive file descriptor if needed
	 */
	ret = recv_fds_from_worker(worker, cmd, ret_value);
	if (ret < 0) {
		ERR("Error receiving fd");
		ret = -1;
		ret_value->_errno = EIO;
	}

end:
	return ret;
}

/*
 * This is for debugging ONLY and should not be considered secure.
 */
static int run_as_noworker(enum run_as_cmd cmd,
			   struct run_as_data *data,
			   struct run_as_ret *ret_value,
			   uid_t uid __attribute__((unused)),
			   gid_t gid __attribute__((unused)))
{
	int ret, saved_errno;
	mode_t old_mask;
	run_as_fct fct;

	fct = run_as_enum_to_fct(cmd);
	if (!fct) {
		errno = -ENOSYS;
		ret = -1;
		goto end;
	}
	old_mask = umask(0);
	ret = fct(data, ret_value);
	saved_errno = ret_value->_errno;
	umask(old_mask);
	errno = saved_errno;
end:
	return ret;
}

static int reset_sighandler()
{
	int sig;

	DBG("Resetting run_as worker signal handlers to default");
	for (sig = 1; sig <= 31; sig++) {
		(void) signal(sig, SIG_DFL);
	}
	return 0;
}

static void worker_sighandler(int sig)
{
	const char *signame;

	/*
	 * The worker will inherit its parent's signals since they are part of
	 * the same process group. However, in the case of SIGINT and SIGTERM,
	 * we want to give the worker a chance to teardown gracefully when its
	 * parent closes the command socket.
	 */
	switch (sig) {
	case SIGINT:
		signame = "SIGINT";
		break;
	case SIGTERM:
		signame = "SIGTERM";
		break;
	default:
		signame = nullptr;
	}

	if (signame) {
		DBG("run_as worker received signal %s", signame);
	} else {
		DBG("run_as_worker received signal %d", sig);
	}
}

static int set_worker_sighandlers()
{
	int ret = 0;
	sigset_t sigset;
	struct sigaction sa;

	if ((ret = sigemptyset(&sigset)) < 0) {
		PERROR("sigemptyset");
		goto end;
	}

	sa.sa_handler = worker_sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGINT, &sa, nullptr)) < 0) {
		PERROR("sigaction SIGINT");
		goto end;
	}

	if ((ret = sigaction(SIGTERM, &sa, nullptr)) < 0) {
		PERROR("sigaction SIGTERM");
		goto end;
	}

	DBG("run_as signal handler set for SIGTERM and SIGINT");
end:
	return ret;
}

static int run_as_create_worker_no_lock(const char *procname,
					post_fork_cleanup_cb clean_up_func,
					void *clean_up_user_data)
{
	pid_t pid;
	int i, ret = 0;
	ssize_t readlen;
	struct run_as_ret recvret;
	run_as_worker_data *worker;

	LTTNG_ASSERT(!global_worker);
	if (!use_clone()) {
		/*
		 * Don't initialize a worker, all run_as tasks will be performed
		 * in the current process.
		 */
		ret = 0;
		goto end;
	}
	worker = zmalloc<run_as_worker_data>();
	if (!worker) {
		ret = -ENOMEM;
		goto end;
	}
	worker->procname = strdup(procname);
	if (!worker->procname) {
		ret = -ENOMEM;
		goto error_procname_alloc;
	}
	/* Create unix socket. */
	if (lttcomm_create_anon_unix_socketpair(worker->sockpair) < 0) {
		ret = -1;
		goto error_sock;
	}

	/* Fork worker. */
	pid = fork();
	if (pid < 0) {
		PERROR("fork");
		ret = -1;
		goto error_fork;
	} else if (pid == 0) {
		/* Child */

		reset_sighandler();

		set_worker_sighandlers();

		logger_set_thread_name("Run-as worker", true);

		if (clean_up_func) {
			if (clean_up_func(clean_up_user_data) < 0) {
				ERR("Run-as post-fork clean-up failed, exiting.");
				exit(EXIT_FAILURE);
			}
		}

		/* Just close, no shutdown. */
		if (close(worker->sockpair[0])) {
			PERROR("close");
			exit(EXIT_FAILURE);
		}

		/*
		 * Close all FDs aside from STDIN, STDOUT, STDERR and sockpair[1]
		 * Sockpair[1] is used as a control channel with the master
		 */
		for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
			if (i != worker->sockpair[1]) {
				(void) close(i);
			}
		}

		worker->sockpair[0] = -1;
		ret = run_as_worker(worker);
		if (lttcomm_close_unix_sock(worker->sockpair[1])) {
			PERROR("close");
			ret = -1;
		}
		worker->sockpair[1] = -1;
		free(worker->procname);
		free(worker);
		LOG(ret ? PRINT_ERR : PRINT_DBG, "run_as worker exiting (ret = %d)", ret);
		exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
	} else {
		/* Parent */

		/* Just close, no shutdown. */
		if (close(worker->sockpair[1])) {
			PERROR("close");
			ret = -1;
			goto error_fork;
		}
		worker->sockpair[1] = -1;
		worker->pid = pid;
		/* Wait for worker to become ready. */
		readlen = lttcomm_recv_unix_sock(worker->sockpair[0], &recvret, sizeof(recvret));
		if (readlen < sizeof(recvret)) {
			ERR("readlen: %zd", readlen);
			PERROR("Error reading response from run_as at creation");
			ret = -1;
			goto error_fork;
		}
		global_worker = worker;
	}
end:
	return ret;

	/* Error handling. */
error_fork:
	for (i = 0; i < 2; i++) {
		if (worker->sockpair[i] < 0) {
			continue;
		}
		if (lttcomm_close_unix_sock(worker->sockpair[i])) {
			PERROR("close");
		}
		worker->sockpair[i] = -1;
	}
error_sock:
	free(worker->procname);
error_procname_alloc:
	free(worker);
	return ret;
}

static void run_as_destroy_worker_no_lock()
{
	run_as_worker_data *worker = global_worker;

	DBG("Destroying run_as worker");
	if (!worker) {
		return;
	}
	/* Close unix socket */
	DBG("Closing run_as worker socket");
	if (lttcomm_close_unix_sock(worker->sockpair[0])) {
		PERROR("close");
	}
	worker->sockpair[0] = -1;
	/* Wait for worker. */
	for (;;) {
		int status;
		pid_t wait_ret;

		wait_ret = waitpid(worker->pid, &status, 0);
		if (wait_ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			PERROR("waitpid");
			break;
		}

		if (WIFEXITED(status)) {
			LOG(WEXITSTATUS(status) == 0 ? PRINT_DBG : PRINT_ERR,
			    DEFAULT_RUN_AS_WORKER_NAME " terminated with status code %d",
			    WEXITSTATUS(status));
			break;
		} else if (WIFSIGNALED(status)) {
			ERR(DEFAULT_RUN_AS_WORKER_NAME " was killed by signal %d",
			    WTERMSIG(status));
			break;
		}
	}
	free(worker->procname);
	free(worker);
	global_worker = nullptr;
}

static int run_as_restart_worker(run_as_worker_data *worker)
{
	int ret = 0;
	char *procname = nullptr;

	procname = worker->procname;

	/* Close socket to run_as worker process and clean up the zombie process */
	run_as_destroy_worker_no_lock();

	/* Create a new run_as worker process*/
	ret = run_as_create_worker_no_lock(procname, nullptr, nullptr);
	if (ret < 0) {
		ERR("Restarting the worker process failed");
		ret = -1;
		goto err;
	}
err:
	return ret;
}

static int run_as(enum run_as_cmd cmd,
		  struct run_as_data *data,
		  struct run_as_ret *ret_value,
		  uid_t uid,
		  gid_t gid)
{
	int ret, saved_errno;

	pthread_mutex_lock(&worker_lock);
	if (use_clone()) {
		DBG("Using run_as worker");

		LTTNG_ASSERT(global_worker);

		ret = run_as_cmd(global_worker, cmd, data, ret_value, uid, gid);
		saved_errno = ret_value->_errno;

		/*
		 * If the worker thread crashed the errno is set to EIO. we log
		 * the error and  start a new worker process.
		 */
		if (ret == -1 && saved_errno == EIO) {
			DBG("Socket closed unexpectedly... "
			    "Restarting the worker process");
			ret = run_as_restart_worker(global_worker);
			if (ret == -1) {
				ERR("Failed to restart worker process.");
				goto err;
			}
		}
	} else {
		DBG("Using run_as without worker");
		ret = run_as_noworker(cmd, data, ret_value, uid, gid);
	}
err:
	pthread_mutex_unlock(&worker_lock);
	return ret;
}

int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat_recursive(AT_FDCWD, path, mode, uid, gid);
}

int run_as_mkdirat_recursive(int dirfd, const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("mkdirat() recursive fd = %d%s, path = %s, mode = %d, uid = %d, gid = %d",
	     dirfd,
	     dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     path,
	     (int) mode,
	     (int) uid,
	     (int) gid);
	ret = lttng_strncpy(data.u.mkdir.path, path, sizeof(data.u.mkdir.path));
	if (ret) {
		ERR("Failed to copy path argument of mkdirat recursive command");
		goto error;
	}
	data.u.mkdir.path[sizeof(data.u.mkdir.path) - 1] = '\0';
	data.u.mkdir.mode = mode;
	data.u.mkdir.dirfd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_MKDIR_RECURSIVE : RUN_AS_MKDIRAT_RECURSIVE,
	       &data,
	       &run_as_ret,
	       uid,
	       gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.ret;
error:
	return ret;
}

int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat(AT_FDCWD, path, mode, uid, gid);
}

int run_as_mkdirat(int dirfd, const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("mkdirat() recursive fd = %d%s, path = %s, mode = %d, uid = %d, gid = %d",
	     dirfd,
	     dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     path,
	     (int) mode,
	     (int) uid,
	     (int) gid);
	ret = lttng_strncpy(data.u.mkdir.path, path, sizeof(data.u.mkdir.path));
	if (ret) {
		ERR("Failed to copy path argument of mkdirat command");
		goto error;
	}
	data.u.mkdir.path[sizeof(data.u.mkdir.path) - 1] = '\0';
	data.u.mkdir.mode = mode;
	data.u.mkdir.dirfd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_MKDIR : RUN_AS_MKDIRAT, &data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.ret;
error:
	return ret;
}

int run_as_open(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_openat(AT_FDCWD, path, flags, mode, uid, gid);
}

int run_as_openat(int dirfd, const char *path, int flags, mode_t mode, uid_t uid, gid_t gid)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("openat() fd = %d%s, path = %s, flags = %X, mode = %d, uid %d, gid %d",
	     dirfd,
	     dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     path,
	     flags,
	     (int) mode,
	     (int) uid,
	     (int) gid);
	ret = lttng_strncpy(data.u.open.path, path, sizeof(data.u.open.path));
	if (ret) {
		ERR("Failed to copy path argument of open command");
		goto error;
	}
	data.u.open.flags = flags;
	data.u.open.mode = mode;
	data.u.open.dirfd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_OPEN : RUN_AS_OPENAT, &data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.ret < 0 ? run_as_ret.u.ret : run_as_ret.u.open.fd;
error:
	return ret;
}

int run_as_unlink(const char *path, uid_t uid, gid_t gid)
{
	return run_as_unlinkat(AT_FDCWD, path, uid, gid);
}

int run_as_unlinkat(int dirfd, const char *path, uid_t uid, gid_t gid)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("unlinkat() fd = %d%s, path = %s, uid = %d, gid = %d",
	     dirfd,
	     dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     path,
	     (int) uid,
	     (int) gid);
	ret = lttng_strncpy(data.u.unlink.path, path, sizeof(data.u.unlink.path));
	if (ret) {
		goto error;
	}
	data.u.unlink.dirfd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_UNLINK : RUN_AS_UNLINKAT, &data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.ret;
error:
	return ret;
}

int run_as_rmdir(const char *path, uid_t uid, gid_t gid)
{
	return run_as_rmdirat(AT_FDCWD, path, uid, gid);
}

int run_as_rmdirat(int dirfd, const char *path, uid_t uid, gid_t gid)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("rmdirat() fd = %d%s, path = %s, uid = %d, gid = %d",
	     dirfd,
	     dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     path,
	     (int) uid,
	     (int) gid);
	ret = lttng_strncpy(data.u.rmdir.path, path, sizeof(data.u.rmdir.path));
	if (ret) {
		goto error;
	}
	data.u.rmdir.dirfd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_RMDIR : RUN_AS_RMDIRAT, &data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.ret;
error:
	return ret;
}

int run_as_rmdir_recursive(const char *path, uid_t uid, gid_t gid, int flags)
{
	return run_as_rmdirat_recursive(AT_FDCWD, path, uid, gid, flags);
}

int run_as_rmdirat_recursive(int dirfd, const char *path, uid_t uid, gid_t gid, int flags)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("rmdirat() recursive fd = %d%s, path = %s, uid = %d, gid = %d",
	     dirfd,
	     dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     path,
	     (int) uid,
	     (int) gid);
	ret = lttng_strncpy(data.u.rmdir.path, path, sizeof(data.u.rmdir.path));
	if (ret) {
		goto error;
	}
	data.u.rmdir.dirfd = dirfd;
	data.u.rmdir.flags = flags;
	run_as(dirfd == AT_FDCWD ? RUN_AS_RMDIR_RECURSIVE : RUN_AS_RMDIRAT_RECURSIVE,
	       &data,
	       &run_as_ret,
	       uid,
	       gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.ret;
error:
	return ret;
}

int run_as_rename(const char *old_name, const char *new_name, uid_t uid, gid_t gid)
{
	return run_as_renameat(AT_FDCWD, old_name, AT_FDCWD, new_name, uid, gid);
}

int run_as_renameat(int old_dirfd,
		    const char *old_name,
		    int new_dirfd,
		    const char *new_name,
		    uid_t uid,
		    gid_t gid)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("renameat() old_dirfd = %d%s, old_name = %s, new_dirfd = %d%s, new_name = %s, uid = %d, gid = %d",
	     old_dirfd,
	     old_dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     old_name,
	     new_dirfd,
	     new_dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
	     new_name,
	     (int) uid,
	     (int) gid);
	ret = lttng_strncpy(data.u.rename.old_path, old_name, sizeof(data.u.rename.old_path));
	if (ret) {
		goto error;
	}
	ret = lttng_strncpy(data.u.rename.new_path, new_name, sizeof(data.u.rename.new_path));
	if (ret) {
		goto error;
	}

	data.u.rename.dirfds[0] = old_dirfd;
	data.u.rename.dirfds[1] = new_dirfd;
	run_as(old_dirfd == AT_FDCWD && new_dirfd == AT_FDCWD ? RUN_AS_RENAME : RUN_AS_RENAMEAT,
	       &data,
	       &run_as_ret,
	       uid,
	       gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.ret;
error:
	return ret;
}

int run_as_extract_elf_symbol_offset(
	int fd, const char *function, uid_t uid, gid_t gid, uint64_t *offset)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("extract_elf_symbol_offset() on fd=%d and function=%s "
	     "with for uid %d and gid %d",
	     fd,
	     function,
	     (int) uid,
	     (int) gid);

	data.u.extract_elf_symbol_offset.fd = fd;

	strncpy(data.u.extract_elf_symbol_offset.function, function, LTTNG_SYMBOL_NAME_LEN - 1);
	data.u.extract_elf_symbol_offset.function[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
	ret = lttng_strncpy(data.u.extract_elf_symbol_offset.function,
			    function,
			    sizeof(data.u.extract_elf_symbol_offset.function));
	if (ret) {
		goto error;
	}

	run_as(RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET, &data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	if (run_as_ret._error) {
		ret = -1;
		goto error;
	}

	*offset = run_as_ret.u.extract_elf_symbol_offset.offset;
error:
	return ret;
}

int run_as_extract_sdt_probe_offsets(int fd,
				     const char *provider_name,
				     const char *probe_name,
				     uid_t uid,
				     gid_t gid,
				     uint64_t **offsets,
				     uint32_t *num_offset)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};

	DBG3("extract_sdt_probe_offsets() on fd=%d, probe_name=%s and "
	     "provider_name=%s with for uid %d and gid %d",
	     fd,
	     probe_name,
	     provider_name,
	     (int) uid,
	     (int) gid);

	data.u.extract_sdt_probe_offsets.fd = fd;

	ret = lttng_strncpy(data.u.extract_sdt_probe_offsets.probe_name,
			    probe_name,
			    sizeof(data.u.extract_sdt_probe_offsets.probe_name));
	if (ret) {
		goto error;
	}
	ret = lttng_strncpy(data.u.extract_sdt_probe_offsets.provider_name,
			    provider_name,
			    sizeof(data.u.extract_sdt_probe_offsets.provider_name));
	if (ret) {
		goto error;
	}

	run_as(RUN_AS_EXTRACT_SDT_PROBE_OFFSETS, &data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	if (run_as_ret._error) {
		ret = -1;
		goto error;
	}

	*num_offset = run_as_ret.u.extract_sdt_probe_offsets.num_offset;
	*offsets = calloc<uint64_t>(*num_offset);
	if (!*offsets) {
		ret = -ENOMEM;
		goto error;
	}

	memcpy(*offsets,
	       run_as_ret.u.extract_sdt_probe_offsets.offsets,
	       *num_offset * sizeof(uint64_t));
error:
	return ret;
}

int run_as_generate_filter_bytecode(const char *filter_expression,
				    const struct lttng_credentials *creds,
				    struct lttng_bytecode **bytecode)
{
	int ret;
	struct run_as_data data = {};
	struct run_as_ret run_as_ret = {};
	const struct lttng_bytecode *view_bytecode = nullptr;
	struct lttng_bytecode *local_bytecode = nullptr;
	const uid_t uid = lttng_credentials_get_uid(creds);
	const gid_t gid = lttng_credentials_get_gid(creds);

	DBG3("generate_filter_bytecode() from expression=\"%s\" for uid %d and gid %d",
	     filter_expression,
	     (int) uid,
	     (int) gid);

	ret = lttng_strncpy(data.u.generate_filter_bytecode.filter_expression,
			    filter_expression,
			    sizeof(data.u.generate_filter_bytecode.filter_expression));
	if (ret) {
		goto error;
	}

	run_as(RUN_AS_GENERATE_FILTER_BYTECODE, &data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	if (run_as_ret._error) {
		ret = -1;
		goto error;
	}

	view_bytecode =
		(const struct lttng_bytecode *) run_as_ret.u.generate_filter_bytecode.bytecode;

	local_bytecode = calloc<lttng_bytecode>(view_bytecode->len);
	if (!local_bytecode) {
		ret = -ENOMEM;
		goto error;
	}

	memcpy(local_bytecode,
	       run_as_ret.u.generate_filter_bytecode.bytecode,
	       sizeof(*local_bytecode) + view_bytecode->len);
	*bytecode = local_bytecode;
error:
	return ret;
}

int run_as_create_worker(const char *procname,
			 post_fork_cleanup_cb clean_up_func,
			 void *clean_up_user_data)
{
	int ret;

	pthread_mutex_lock(&worker_lock);
	ret = run_as_create_worker_no_lock(procname, clean_up_func, clean_up_user_data);
	pthread_mutex_unlock(&worker_lock);
	return ret;
}

void run_as_destroy_worker()
{
	pthread_mutex_lock(&worker_lock);
	run_as_destroy_worker_no_lock();
	pthread_mutex_unlock(&worker_lock);
}
