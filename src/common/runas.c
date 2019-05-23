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

#define _LGPL_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <assert.h>
#include <signal.h>

#include <common/lttng-kernel.h>
#include <common/common.h>
#include <common/utils.h>
#include <common/compat/getenv.h>
#include <common/compat/prctl.h>
#include <common/unix.h>
#include <common/defaults.h>
#include <common/lttng-elf.h>

#include <lttng/constant.h>

#include "runas.h"

struct run_as_data;
struct run_as_ret;
typedef int (*run_as_fct)(struct run_as_data *data, struct run_as_ret *ret_value);

struct run_as_mkdirat_data {
	char path[PATH_MAX];
	mode_t mode;
};

struct run_as_open_data {
	char path[PATH_MAX];
	int flags;
	mode_t mode;
};

struct run_as_unlink_data {
	char path[PATH_MAX];
};

struct run_as_rmdir_recursive_data {
	char path[PATH_MAX];
};

struct run_as_extract_elf_symbol_offset_data {
	char function[LTTNG_SYMBOL_NAME_LEN];
};

struct run_as_extract_sdt_probe_offsets_data {
	char probe_name[LTTNG_SYMBOL_NAME_LEN];
	char provider_name[LTTNG_SYMBOL_NAME_LEN];
};

struct run_as_mkdirat_ret {
	int ret;
};

struct run_as_open_ret {
	int ret;
};

struct run_as_unlink_ret {
	int ret;
};

struct run_as_rmdir_recursive_ret {
	int ret;
};

struct run_as_extract_elf_symbol_offset_ret {
	uint64_t offset;
};

struct run_as_extract_sdt_probe_offsets_ret {
	uint32_t num_offset;
	uint64_t offsets[LTTNG_KERNEL_MAX_UPROBE_NUM];
};

enum run_as_cmd {
	RUN_AS_MKDIR,
	RUN_AS_MKDIRAT,
	RUN_AS_MKDIR_RECURSIVE,
	RUN_AS_MKDIRAT_RECURSIVE,
	RUN_AS_OPEN,
	RUN_AS_OPENAT,
	RUN_AS_UNLINK,
	RUN_AS_UNLINKAT,
	RUN_AS_RMDIR_RECURSIVE,
	RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET,
	RUN_AS_EXTRACT_SDT_PROBE_OFFSETS,
};

struct run_as_data {
	enum run_as_cmd cmd;
	int fd;
	union {
		struct run_as_mkdirat_data mkdirat;
		struct run_as_open_data open;
		struct run_as_unlink_data unlink;
		struct run_as_rmdir_recursive_data rmdir_recursive;
		struct run_as_extract_elf_symbol_offset_data extract_elf_symbol_offset;
		struct run_as_extract_sdt_probe_offsets_data extract_sdt_probe_offsets;
	} u;
	uid_t uid;
	gid_t gid;
};

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
	int fd;
	union {
		struct run_as_mkdirat_ret mkdirat;
		struct run_as_open_ret open;
		struct run_as_unlink_ret unlink;
		struct run_as_rmdir_recursive_ret rmdir_recursive;
		struct run_as_extract_elf_symbol_offset_ret extract_elf_symbol_offset;
		struct run_as_extract_sdt_probe_offsets_ret extract_sdt_probe_offsets;
	} u;
	int _errno;
	bool _error;
};

struct run_as_worker {
	pid_t pid;	/* Worker PID. */
	int sockpair[2];
	char *procname;
};

/* Single global worker per process (for now). */
static struct run_as_worker *global_worker;
/* Lock protecting the worker. */
static pthread_mutex_t worker_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef VALGRIND
static
int use_clone(void)
{
	return 0;
}
#else
static
int use_clone(void)
{
	return !lttng_secure_getenv("LTTNG_DEBUG_NOCLONE");
}
#endif

/*
 * Create recursively directory using the FULL path.
 */
static
int _mkdirat_recursive(struct run_as_data *data, struct run_as_ret *ret_value)
{
	const char *path;
	mode_t mode;
	struct lttng_directory_handle handle;

	path = data->u.mkdirat.path;
	mode = data->u.mkdirat.mode;

	(void) lttng_directory_handle_init_from_dirfd(&handle, data->fd);
	/* Ownership of dirfd is transferred to the handle. */
	data->fd = -1;
	/* Safe to call as we have transitioned to the requested uid/gid. */
	ret_value->u.mkdirat.ret =
			lttng_directory_handle_create_subdirectory_recursive(
					&handle, path, mode);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.mkdirat.ret) ? true : false;
	lttng_directory_handle_fini(&handle);
	return ret_value->u.mkdirat.ret;
}

static
int _mkdirat(struct run_as_data *data, struct run_as_ret *ret_value)
{
	const char *path;
	mode_t mode;
	struct lttng_directory_handle handle;

	path = data->u.mkdirat.path;
	mode = data->u.mkdirat.mode;

	(void) lttng_directory_handle_init_from_dirfd(&handle, data->fd);
	/* Ownership of dirfd is transferred to the handle. */
	data->fd = -1;
	/* Safe to call as we have transitioned to the requested uid/gid. */
	ret_value->u.mkdirat.ret =
			lttng_directory_handle_create_subdirectory(
					&handle, path, mode);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.mkdirat.ret) ? true : false;
	lttng_directory_handle_fini(&handle);
	return ret_value->u.mkdirat.ret;
}

static
int _open(struct run_as_data *data, struct run_as_ret *ret_value)
{
	ret_value->u.open.ret = openat(data->fd, data->u.open.path,
			data->u.open.flags, data->u.open.mode);
	ret_value->fd = ret_value->u.open.ret;
	ret_value->_errno = errno;
	ret_value->_error = ret_value->u.open.ret < 0;
	return ret_value->u.open.ret;
}

static
int _unlink(struct run_as_data *data, struct run_as_ret *ret_value)
{
	ret_value->u.unlink.ret = unlinkat(data->fd, data->u.unlink.path, 0);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.unlink.ret) ? true : false;
	return ret_value->u.unlink.ret;
}

static
int _rmdir_recursive(struct run_as_data *data, struct run_as_ret *ret_value)
{
	ret_value->u.rmdir_recursive.ret = utils_recursive_rmdir(data->u.rmdir_recursive.path);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.rmdir_recursive.ret) ? true : false;
	return ret_value->u.rmdir_recursive.ret;
}

#ifdef HAVE_ELF_H
static
int _extract_elf_symbol_offset(struct run_as_data *data,
		struct run_as_ret *ret_value)
{
	int ret = 0;
	ret_value->_error = false;

	ret = lttng_elf_get_symbol_offset(data->fd,
			 data->u.extract_elf_symbol_offset.function,
			 &ret_value->u.extract_elf_symbol_offset.offset);
	if (ret) {
		DBG("Failed to extract ELF function offset");
		ret_value->_error = true;
	}

	return ret;
}

static
int _extract_sdt_probe_offsets(struct run_as_data *data,
		struct run_as_ret *ret_value)
{
	int ret = 0;
	uint64_t *offsets = NULL;
	uint32_t num_offset;

	ret_value->_error = false;

	/* On success, this call allocates the offsets paramater. */
	ret = lttng_elf_get_sdt_probe_offsets(data->fd,
			data->u.extract_sdt_probe_offsets.provider_name,
			data->u.extract_sdt_probe_offsets.probe_name,
			&offsets, &num_offset);

	if (ret) {
		DBG("Failed to extract SDT probe offsets");
		ret_value->_error = true;
		goto end;
	}

	if (num_offset <= 0 || num_offset > LTTNG_KERNEL_MAX_UPROBE_NUM) {
		DBG("Wrong number of probes.");
		ret = -1;
		ret_value->_error = true;
		goto free_offset;
	}

	/* Copy the content of the offsets array to the ret struct. */
	memcpy(ret_value->u.extract_sdt_probe_offsets.offsets,
			offsets, num_offset * sizeof(uint64_t));

	ret_value->u.extract_sdt_probe_offsets.num_offset = num_offset;

free_offset:
	free(offsets);
end:
	return ret;
}
#else
static
int _extract_elf_symbol_offset(struct run_as_data *data,
		struct run_as_ret *ret_value)
{
	ERR("Unimplemented runas command RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET");
	return -1;
}

static
int _extract_sdt_probe_offsets(struct run_as_data *data,
		struct run_as_ret *ret_value)
{
	ERR("Unimplemented runas command RUN_AS_EXTRACT_SDT_PROBE_OFFSETS");
	return -1;
}
#endif

static
run_as_fct run_as_enum_to_fct(enum run_as_cmd cmd)
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
	case RUN_AS_RMDIR_RECURSIVE:
		return _rmdir_recursive;
	case RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET:
		return _extract_elf_symbol_offset;
	case RUN_AS_EXTRACT_SDT_PROBE_OFFSETS:
		return _extract_sdt_probe_offsets;
	default:
		ERR("Unknown command %d", (int) cmd);
		return NULL;
	}
}

static
int do_send_fd(int sock, int fd)
{
	ssize_t len;

	if (fd < 0) {
		ERR("Attempt to send invalid file descriptor to master (fd = %i)", fd);
		/* Return 0 as this is not a fatal error. */
		return 0;
	}

	len = lttcomm_send_fds_unix_sock(sock, &fd, 1);
	if (len < 0) {
		PERROR("lttcomm_send_fds_unix_sock");
		return -1;
	}
	return 0;
}

static
int do_recv_fd(int sock, int *fd)
{
	ssize_t len;

	len = lttcomm_recv_fds_unix_sock(sock, fd, 1);

	if (!len) {
		return -1;
	} else if (len < 0) {
		PERROR("lttcomm_recv_fds_unix_sock");
		return -1;
	}
	if (*fd < 0) {
		ERR("Invalid file descriptor received from worker (fd = %i)", *fd);
		/* Return 0 as this is not a fatal error. */
		return 0;
	}

	return 0;
}

static
int send_fd_to_worker(struct run_as_worker *worker, enum run_as_cmd cmd, int fd)
{
	int ret = 0;

	switch (cmd) {
	case RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET:
	case RUN_AS_EXTRACT_SDT_PROBE_OFFSETS:
	case RUN_AS_MKDIRAT:
	case RUN_AS_MKDIRAT_RECURSIVE:
	case RUN_AS_OPENAT:
	case RUN_AS_UNLINKAT:
		break;
	default:
		return 0;
	}

	if (fd < 0) {
		ERR("Refusing to send invalid fd to worker (fd = %i)", fd);
		return -1;
	}

	ret = do_send_fd(worker->sockpair[0], fd);
	if (ret < 0) {
		PERROR("do_send_fd");
		ret = -1;
	}

	return ret;
}

static
int send_fd_to_master(struct run_as_worker *worker, enum run_as_cmd cmd, int fd)
{
	int ret = 0, ret_close = 0;

	switch (cmd) {
	case RUN_AS_OPEN:
	case RUN_AS_OPENAT:
		break;
	default:
		return 0;
	}

	if (fd < 0) {
		DBG("Not sending file descriptor to master as it is invalid (fd = %i)", fd);
		return 0;
	}
	ret = do_send_fd(worker->sockpair[1], fd);
	if (ret < 0) {
		PERROR("do_send_fd error");
		ret = -1;
	}

	ret_close = close(fd);
	if (ret_close < 0) {
		PERROR("close");
	}

	return ret;
}

static
int recv_fd_from_worker(struct run_as_worker *worker, enum run_as_cmd cmd, int *fd)
{
	int ret = 0;

	switch (cmd) {
	case RUN_AS_OPEN:
	case RUN_AS_OPENAT:
		break;
	default:
		return 0;
	}

	ret = do_recv_fd(worker->sockpair[0], fd);
	if (ret < 0) {
		PERROR("do_recv_fd error");
		ret = -1;
	}

	return ret;
}

static
int recv_fd_from_master(struct run_as_worker *worker, enum run_as_cmd cmd, int *fd)
{
	int ret = 0;

	switch (cmd) {
	case RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET:
	case RUN_AS_EXTRACT_SDT_PROBE_OFFSETS:
	case RUN_AS_MKDIRAT:
	case RUN_AS_MKDIRAT_RECURSIVE:
	case RUN_AS_OPENAT:
	case RUN_AS_UNLINKAT:
		break;
	case RUN_AS_MKDIR:
	case RUN_AS_MKDIR_RECURSIVE:
	case RUN_AS_OPEN:
	case RUN_AS_UNLINK:
		*fd = AT_FDCWD;
		/* fall-through */
	default:
		return 0;
	}

	ret = do_recv_fd(worker->sockpair[1], fd);
	if (ret < 0) {
		PERROR("do_recv_fd error");
		ret = -1;
	}

	return ret;
}

static
int cleanup_received_fd(enum run_as_cmd cmd, int fd)
{
	int ret = 0;

	switch (cmd) {
	case RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET:
	case RUN_AS_EXTRACT_SDT_PROBE_OFFSETS:
	case RUN_AS_MKDIRAT:
	case RUN_AS_MKDIRAT_RECURSIVE:
	case RUN_AS_OPEN:
	case RUN_AS_OPENAT:
	case RUN_AS_UNLINK:
	case RUN_AS_UNLINKAT:
		break;
	default:
		return 0;
	}

	if (fd < 0) {
		return 0;
	}
	ret = close(fd);
	if (ret < 0) {
		PERROR("close error");
		ret = -1;
	}

	return ret;
}

/*
 * Return < 0 on error, 0 if OK, 1 on hangup.
 */
static
int handle_one_cmd(struct run_as_worker *worker)
{
	int ret = 0;
	struct run_as_data data;
	ssize_t readlen, writelen;
	struct run_as_ret sendret;
	run_as_fct cmd;
	uid_t prev_euid;

	memset(&sendret, 0, sizeof(sendret));
	sendret.fd = -1;

	/*
	 * Stage 1: Receive run_as_data struct from the master.
	 * The structure contains the command type and all the parameters needed for
	 * its execution
	 */
	readlen = lttcomm_recv_unix_sock(worker->sockpair[1], &data,
			sizeof(data));
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
	ret = recv_fd_from_master(worker, data.cmd, &data.fd);
	if (ret < 0) {
		PERROR("recv_fd_from_master error");
		ret = -1;
		goto end;
	}

	prev_euid = getuid();
	if (data.gid != getegid()) {
		ret = setegid(data.gid);
		if (ret < 0) {
			sendret._error = true;
			sendret._errno = errno;
			PERROR("setegid");
			goto write_return;
		}
	}
	if (data.uid != prev_euid) {
		ret = seteuid(data.uid);
		if (ret < 0) {
			sendret._error = true;
			sendret._errno = errno;
			PERROR("seteuid");
			goto write_return;
		}
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
	ret = cleanup_received_fd(data.cmd, data.fd);
	if (ret < 0) {
		ERR("Error cleaning up FD");
		goto end;
	}

	/*
	 * Stage 4: Send run_as_ret structure to the master.
	 * This structure contain the return value of the command and the errno.
	 */
	writelen = lttcomm_send_unix_sock(worker->sockpair[1], &sendret,
			sizeof(sendret));
	if (writelen < sizeof(sendret)) {
		PERROR("lttcomm_send_unix_sock error");
		ret = -1;
		goto end;
	}

	/*
	 * Stage 5: Send file descriptor to the master
	 * Some commands return a file descriptor so if it's needed we pass it back
	 * to the master using the Unix socket.
	 */
	ret = send_fd_to_master(worker, data.cmd, sendret.fd);
	if (ret < 0) {
		DBG("Sending FD to master returned an error");
		goto end;
	}

	if (seteuid(prev_euid) < 0) {
		PERROR("seteuid");
		ret = -1;
		goto end;
	}
	ret = 0;
end:
	return ret;
}

static
int run_as_worker(struct run_as_worker *worker)
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

	ret = lttng_prctl(PR_SET_NAME,
			(unsigned long) DEFAULT_RUN_AS_WORKER_NAME, 0, 0, 0);
	if (ret && ret != -ENOSYS) {
		/* Don't fail as this is not essential. */
		PERROR("prctl PR_SET_NAME");
	}

	memset(&sendret, 0, sizeof(sendret));

	writelen = lttcomm_send_unix_sock(worker->sockpair[1], &sendret,
			sizeof(sendret));
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
			continue;	/* Next command. */
		}
	}
	ret = EXIT_SUCCESS;
end:
	return ret;
}

static
int run_as_cmd(struct run_as_worker *worker,
		enum run_as_cmd cmd,
		struct run_as_data *data,
		struct run_as_ret *ret_value,
		uid_t uid, gid_t gid)
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
				(int) uid, (int) geteuid());
			goto end;
		}
	}

	data->cmd = cmd;
	data->uid = uid;
	data->gid = gid;

	/*
	 * Stage 1: Send the run_as_data struct to the worker process
	 */
	writelen = lttcomm_send_unix_sock(worker->sockpair[0], data,
			sizeof(*data));
	if (writelen < sizeof(*data)) {
		PERROR("Error writing message to run_as");
		ret = -1;
		ret_value->_errno = EIO;
		goto end;
	}

	/*
	 * Stage 2: Send file descriptor to the worker process if needed
	 */
	ret = send_fd_to_worker(worker, data->cmd, data->fd);
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
	readlen = lttcomm_recv_unix_sock(worker->sockpair[0], ret_value,
			sizeof(*ret_value));
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
	ret = recv_fd_from_worker(worker, data->cmd, &ret_value->fd);
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
static
int run_as_noworker(enum run_as_cmd cmd,
		struct run_as_data *data, struct run_as_ret *ret_value,
		uid_t uid, gid_t gid)
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

static
int reset_sighandler(void)
{
	int sig;

	DBG("Resetting run_as worker signal handlers to default");
	for (sig = 1; sig <= 31; sig++) {
		(void) signal(sig, SIG_DFL);
	}
	return 0;
}

static
void worker_sighandler(int sig)
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
		signame = NULL;
	}

	if (signame) {
		DBG("run_as worker received signal %s", signame);
	} else {
		DBG("run_as_worker received signal %d", sig);
	}
}

static
int set_worker_sighandlers(void)
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
	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		PERROR("sigaction SIGINT");
		goto end;
	}

	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		PERROR("sigaction SIGTERM");
		goto end;
	}

	DBG("run_as signal handler set for SIGTERM and SIGINT");
end:
	return ret;
}

static
int run_as_create_worker_no_lock(const char *procname,
		post_fork_cleanup_cb clean_up_func,
		void *clean_up_user_data)
{
	pid_t pid;
	int i, ret = 0;
	ssize_t readlen;
	struct run_as_ret recvret;
	struct run_as_worker *worker;

	assert(!global_worker);
	if (!use_clone()) {
		/*
		 * Don't initialize a worker, all run_as tasks will be performed
		 * in the current process.
		 */
		ret = 0;
		goto end;
	}
	worker = zmalloc(sizeof(*worker));
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
		readlen = lttcomm_recv_unix_sock(worker->sockpair[0],
				&recvret, sizeof(recvret));
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

static
void run_as_destroy_worker_no_lock(void)
{
	struct run_as_worker *worker = global_worker;

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
	global_worker = NULL;
}

static
int run_as_restart_worker(struct run_as_worker *worker)
{
	int ret = 0;
	char *procname = NULL;

	procname = worker->procname;

	/* Close socket to run_as worker process and clean up the zombie process */
	run_as_destroy_worker_no_lock();

	/* Create a new run_as worker process*/
	ret = run_as_create_worker_no_lock(procname, NULL, NULL);
	if (ret < 0 ) {
		ERR("Restarting the worker process failed");
		ret = -1;
		goto err;
	}
err:
	return ret;
}

static
int run_as(enum run_as_cmd cmd, struct run_as_data *data,
		   struct run_as_ret *ret_value, uid_t uid, gid_t gid)
{
	int ret, saved_errno;

	pthread_mutex_lock(&worker_lock);
	if (use_clone()) {
		DBG("Using run_as worker");

		assert(global_worker);

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

LTTNG_HIDDEN
int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat_recursive(AT_FDCWD, path, mode, uid, gid);
}

LTTNG_HIDDEN
int run_as_mkdirat_recursive(int dirfd, const char *path, mode_t mode,
		uid_t uid, gid_t gid)
{
	int ret;
	struct run_as_data data;
	struct run_as_ret run_as_ret;

	memset(&data, 0, sizeof(data));
	memset(&run_as_ret, 0, sizeof(run_as_ret));
	DBG3("mkdirat() recursive fd = %d%s, path = %s, mode = %d, uid = %d, gid = %d",
			dirfd, dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
			path, (int) mode, (int) uid, (int) gid);
	ret = lttng_strncpy(data.u.mkdirat.path, path,
			sizeof(data.u.mkdirat.path));
	if (ret) {
		ERR("Failed to copy path argument of mkdirat recursive command");
		goto error;
	}
	data.u.mkdirat.path[PATH_MAX - 1] = '\0';
	data.u.mkdirat.mode = mode;
	data.fd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_MKDIR_RECURSIVE : RUN_AS_MKDIRAT_RECURSIVE,
			&data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.mkdirat.ret;
error:
	return ret;
}

LTTNG_HIDDEN
int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	return run_as_mkdirat(AT_FDCWD, path, mode, uid, gid);
}

LTTNG_HIDDEN
int run_as_mkdirat(int dirfd, const char *path, mode_t mode,
		uid_t uid, gid_t gid)
{
	int ret;
	struct run_as_data data;
	struct run_as_ret run_as_ret;

	memset(&data, 0, sizeof(data));
	memset(&run_as_ret, 0, sizeof(run_as_ret));

	DBG3("mkdirat() recursive fd = %d%s, path = %s, mode = %d, uid = %d, gid = %d",
			dirfd, dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
			path, (int) mode, (int) uid, (int) gid);
	ret = lttng_strncpy(data.u.mkdirat.path, path,
			sizeof(data.u.mkdirat.path));
	if (ret) {
		ERR("Failed to copy path argument of mkdirat command");
		goto error;
	}
	data.u.mkdirat.path[PATH_MAX - 1] = '\0';
	data.u.mkdirat.mode = mode;
	data.fd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_MKDIR : RUN_AS_MKDIRAT,
			&data, &run_as_ret, uid, gid);
	errno = run_as_ret._errno;
	ret = run_as_ret.u.mkdirat.ret;
error:
	return ret;
}

LTTNG_HIDDEN
int run_as_open(const char *path, int flags, mode_t mode, uid_t uid,
                gid_t gid)
{
	return run_as_openat(AT_FDCWD, path, flags, mode, uid, gid);
}

LTTNG_HIDDEN
int run_as_openat(int dirfd, const char *path, int flags, mode_t mode,
		uid_t uid, gid_t gid)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("openat() fd = %d%s, path = %s, flags = %X, mode = %d, uid %d, gid %d",
			dirfd, dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
			path, flags, (int) mode, (int) uid, (int) gid);
	strncpy(data.u.open.path, path, PATH_MAX - 1);
	data.u.open.path[PATH_MAX - 1] = '\0';
	data.u.open.flags = flags;
	data.u.open.mode = mode;
	data.fd = dirfd;
	run_as(dirfd == AT_FDCWD ? RUN_AS_OPEN : RUN_AS_OPENAT,
			&data, &ret, uid, gid);
	errno = ret._errno;
	ret.u.open.ret = ret.fd;
	return ret.u.open.ret;
}

LTTNG_HIDDEN
int run_as_unlink(const char *path, uid_t uid, gid_t gid)
{
	return run_as_unlinkat(AT_FDCWD, path, uid, gid);
}

LTTNG_HIDDEN
int run_as_unlinkat(int dirfd, const char *path, uid_t uid, gid_t gid)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("unlinkat() fd = %d%s, path = %s, uid = %d, gid = %d",
			dirfd, dirfd == AT_FDCWD ? " (AT_FDCWD)" : "",
			path, (int) uid, (int) gid);
	strncpy(data.u.unlink.path, path, PATH_MAX - 1);
	data.u.unlink.path[PATH_MAX - 1] = '\0';
	data.fd = dirfd;
	run_as(RUN_AS_UNLINK, &data, &ret, uid, gid);
	errno = ret._errno;
	return ret.u.unlink.ret;
}

LTTNG_HIDDEN
int run_as_rmdir_recursive(const char *path, uid_t uid, gid_t gid)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("rmdir_recursive() %s with for uid %d and gid %d",
			path, (int) uid, (int) gid);
	strncpy(data.u.rmdir_recursive.path, path, PATH_MAX - 1);
	data.u.rmdir_recursive.path[PATH_MAX - 1] = '\0';
	run_as(RUN_AS_RMDIR_RECURSIVE, &data, &ret, uid, gid);
	errno = ret._errno;
	return ret.u.rmdir_recursive.ret;
}

LTTNG_HIDDEN
int run_as_extract_elf_symbol_offset(int fd, const char* function,
		uid_t uid, gid_t gid, uint64_t *offset)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("extract_elf_symbol_offset() on fd=%d and function=%s "
		"with for uid %d and gid %d", fd, function, (int) uid, (int) gid);

	data.fd = fd;

	strncpy(data.u.extract_elf_symbol_offset.function, function, LTTNG_SYMBOL_NAME_LEN - 1);

	data.u.extract_elf_symbol_offset.function[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';

	run_as(RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET, &data, &ret, uid, gid);

	errno = ret._errno;

	if (ret._error) {
		return -1;
	}

	*offset = ret.u.extract_elf_symbol_offset.offset;
	return 0;
}

LTTNG_HIDDEN
int run_as_extract_sdt_probe_offsets(int fd, const char* provider_name,
		const char* probe_name, uid_t uid, gid_t gid,
		uint64_t **offsets, uint32_t *num_offset)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("extract_sdt_probe_offsets() on fd=%d, probe_name=%s and "
		"provider_name=%s with for uid %d and gid %d", fd, probe_name,
		provider_name, (int) uid, (int) gid);

	data.fd = fd;

	strncpy(data.u.extract_sdt_probe_offsets.probe_name, probe_name, LTTNG_SYMBOL_NAME_LEN - 1);
	strncpy(data.u.extract_sdt_probe_offsets.provider_name, provider_name, LTTNG_SYMBOL_NAME_LEN - 1);

	data.u.extract_sdt_probe_offsets.probe_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
	data.u.extract_sdt_probe_offsets.provider_name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';

	run_as(RUN_AS_EXTRACT_SDT_PROBE_OFFSETS, &data, &ret, uid, gid);

	errno = ret._errno;

	if (ret._error) {
		return -1;
	}

	*num_offset = ret.u.extract_sdt_probe_offsets.num_offset;

	*offsets = zmalloc(*num_offset * sizeof(uint64_t));
	if (!*offsets) {
		return -ENOMEM;
	}

	memcpy(*offsets, ret.u.extract_sdt_probe_offsets.offsets, *num_offset * sizeof(uint64_t));
	return 0;
}

LTTNG_HIDDEN
int run_as_create_worker(const char *procname,
		post_fork_cleanup_cb clean_up_func,
		void *clean_up_user_data)
{
	int ret;

	pthread_mutex_lock(&worker_lock);
	ret = run_as_create_worker_no_lock(procname, clean_up_func,
			clean_up_user_data);
	pthread_mutex_unlock(&worker_lock);
	return ret;
}

LTTNG_HIDDEN
void run_as_destroy_worker(void)
{
	pthread_mutex_lock(&worker_lock);
	run_as_destroy_worker_no_lock();
	pthread_mutex_unlock(&worker_lock);
}
