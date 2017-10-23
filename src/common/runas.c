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

#include <common/common.h>
#include <common/utils.h>
#include <common/compat/getenv.h>
#include <common/compat/prctl.h>
#include <common/unix.h>
#include <common/defaults.h>
#include <common/lttng-elf.h>

#include "runas.h"

struct run_as_data;
struct run_as_ret;
typedef int (*run_as_fct)(struct run_as_data *data, struct run_as_ret *ret_value);

struct run_as_mkdir_data {
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
	char function[PATH_MAX];
};

enum run_as_cmd {
	RUN_AS_MKDIR,
	RUN_AS_OPEN,
	RUN_AS_UNLINK,
	RUN_AS_RMDIR_RECURSIVE,
	RUN_AS_MKDIR_RECURSIVE,
	RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET,
};

struct run_as_data {
	enum run_as_cmd cmd;
	int fd;
	union {
		struct run_as_mkdir_data mkdir;
		struct run_as_open_data open;
		struct run_as_unlink_data unlink;
		struct run_as_rmdir_recursive_data rmdir_recursive;
		struct run_as_extract_elf_symbol_offset_data extract_elf_symbol_offset;
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
	union {
		int ret_int;
		uint64_t ret_uint64_t;
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

LTTNG_HIDDEN
int _utils_mkdir_recursive_unsafe(const char *path, mode_t mode);

/*
 * Create recursively directory using the FULL path.
 */
static
int _mkdir_recursive(struct run_as_data *data, struct run_as_ret *ret_value)
{
	const char *path;
	mode_t mode;

	path = data->u.mkdir.path;
	mode = data->u.mkdir.mode;

	/* Safe to call as we have transitioned to the requested uid/gid. */
	ret_value->u.ret_int = _utils_mkdir_recursive_unsafe(path, mode);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret_int) ? true : false;
	return ret_value->u.ret_int;
}

static
int _mkdir(struct run_as_data *data, struct run_as_ret *ret_value)
{
	ret_value->u.ret_int = mkdir(data->u.mkdir.path, data->u.mkdir.mode);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret_int) ? true : false;
	return ret_value->u.ret_int;
}

static
int _open(struct run_as_data *data, struct run_as_ret *ret_value)
{
	ret_value->u.ret_int = open(data->u.open.path, data->u.open.flags, data->u.open.mode);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret_int) ? true : false;
	return ret_value->u.ret_int;
}

static
int _unlink(struct run_as_data *data, struct run_as_ret *ret_value)
{
	ret_value->u.ret_int = unlink(data->u.unlink.path);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret_int) ? true : false;
	return ret_value->u.ret_int;
}

static
int _rmdir_recursive(struct run_as_data *data, struct run_as_ret *ret_value)
{
	ret_value->u.ret_int = utils_recursive_rmdir(data->u.rmdir_recursive.path);
	ret_value->_errno = errno;
	ret_value->_error = (ret_value->u.ret_int) ? true : false;
	return ret_value->u.ret_int;
}

static
int _extract_elf_symbol_offset(struct run_as_data *data,
							   struct run_as_ret *ret_value)
{
	int ret = 0;
	ret_value->_error = false;

	ret = lttng_elf_get_symbol_offset(data->fd,
									 data->u.extract_elf_symbol_offset.function,
									 &ret_value->u.ret_uint64_t);
	if (ret < 0) {
		DBG("Failed to extract ELF function offset");
		ret = -1;
		ret_value->_error = true;
	}

	return ret;
}

static
run_as_fct run_as_enum_to_fct(enum run_as_cmd cmd)
{
	switch (cmd) {
	case RUN_AS_MKDIR:
		return _mkdir;
	case RUN_AS_OPEN:
		return _open;
	case RUN_AS_UNLINK:
		return _unlink;
	case RUN_AS_RMDIR_RECURSIVE:
		return _rmdir_recursive;
	case RUN_AS_MKDIR_RECURSIVE:
		return _mkdir_recursive;
	case RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET:
		return _extract_elf_symbol_offset;
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
		ERR("Invalid file description");
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

	if (*fd < 0) {
		ERR("Invalid file description");
		return 0;
	}

	len = lttcomm_recv_fds_unix_sock(sock, fd, 1);

	if (!len) {
		return -1;
	} else if (len < 0) {
		PERROR("lttcomm_recv_fds_unix_sock");
		return -1;
	}
	return 0;
}

static
int send_fd_to_worker(struct run_as_worker *worker, enum run_as_cmd cmd, int fd)
{
	int ret = 0;

	switch (cmd) {
	case RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET:
		break;
	default:
		return 0;
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
		break;
	default:
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
		break;
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
		break;
	default:
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
			PERROR("setegid");
			goto write_return;
		}
	}
	if (data.uid != prev_euid) {
		ret = seteuid(data.uid);
		if (ret < 0) {
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
	ret = send_fd_to_master(worker, data.cmd, sendret.u.ret_int);
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
		ret_value->_errno = errno;
		goto end;
	}

	/*
	 * Stage 2: Send file descriptor to the worker process if needed
	 */
	ret = send_fd_to_worker(worker, data->cmd, data->fd);
	if (ret) {
		PERROR("do_send_fd error");
		ret = -1;
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
	}

	/*
	 * Stage 5: Receive file descriptor if needed
	 */
	ret = recv_fd_from_worker(worker, data->cmd, &ret_value->u.ret_int);
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
int run_as(enum run_as_cmd cmd, struct run_as_data *data,
		   struct run_as_ret *ret_value, uid_t uid, gid_t gid)
{
	int ret;

	if (use_clone()) {
		DBG("Using run_as worker");
		pthread_mutex_lock(&worker_lock);
		assert(global_worker);
		ret = run_as_cmd(global_worker, cmd, data, ret_value, uid, gid);
		pthread_mutex_unlock(&worker_lock);

	} else {
		DBG("Using run_as without worker");
		ret = run_as_noworker(cmd, data, ret_value, uid, gid);
	}
	return ret;
}

LTTNG_HIDDEN
int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));
	DBG3("mkdir() recursive %s with mode %d for uid %d and gid %d",
			path, (int) mode, (int) uid, (int) gid);
	strncpy(data.u.mkdir.path, path, PATH_MAX - 1);
	data.u.mkdir.path[PATH_MAX - 1] = '\0';
	data.u.mkdir.mode = mode;

	run_as(RUN_AS_MKDIR_RECURSIVE, &data, &ret, uid, gid);
	errno = ret._errno;
	return ret.u.ret_int;
}

LTTNG_HIDDEN
int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("mkdir() %s with mode %d for uid %d and gid %d",
			path, (int) mode, (int) uid, (int) gid);
	strncpy(data.u.mkdir.path, path, PATH_MAX - 1);
	data.u.mkdir.path[PATH_MAX - 1] = '\0';
	data.u.mkdir.mode = mode;
	run_as(RUN_AS_MKDIR, &data, &ret, uid, gid);
	errno = ret._errno;
	return ret.u.ret_int;
}

LTTNG_HIDDEN
int run_as_open(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("open() %s with flags %X mode %d for uid %d and gid %d",
			path, flags, (int) mode, (int) uid, (int) gid);
	strncpy(data.u.open.path, path, PATH_MAX - 1);
	data.u.open.path[PATH_MAX - 1] = '\0';
	data.u.open.flags = flags;
	data.u.open.mode = mode;
	run_as(RUN_AS_OPEN, &data, &ret, uid, gid);
	errno = ret._errno;
	return ret.u.ret_int;
}

LTTNG_HIDDEN
int run_as_unlink(const char *path, uid_t uid, gid_t gid)
{
	struct run_as_data data;
	struct run_as_ret ret;

	memset(&data, 0, sizeof(data));
	memset(&ret, 0, sizeof(ret));

	DBG3("unlink() %s with for uid %d and gid %d",
			path, (int) uid, (int) gid);
	strncpy(data.u.unlink.path, path, PATH_MAX - 1);
	data.u.unlink.path[PATH_MAX - 1] = '\0';
	run_as(RUN_AS_UNLINK, &data, &ret, uid, gid);
	errno = ret._errno;
	return ret.u.ret_int;
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
	return ret.u.ret_int;
}

LTTNG_HIDDEN
int run_as_extract_elf_symbol_offset(int fd, const char* function,
				    uid_t uid, gid_t gid, uint64_t *offset)
{
	struct run_as_data data;
	struct run_as_ret ret;

	DBG3("extract_elf_symbol_offset() on fd=%d and function=%s "
	     "with for uid %d and gid %d", fd, function, (int) uid, (int) gid);

	data.fd = fd;

	strncpy(data.u.extract_elf_symbol_offset.function, function, PATH_MAX - 1);

	data.u.extract_elf_symbol_offset.function[PATH_MAX - 1] = '\0';

	run_as(RUN_AS_EXTRACT_ELF_SYMBOL_OFFSET, &data, &ret, uid, gid);

	errno = ret._errno;

	if (ret._error != 0) {
		return -1;
	}

	*offset = ret.u.ret_uint64_t;
	return 0;
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

LTTNG_HIDDEN
int run_as_create_worker(char *procname)
{
	pid_t pid;
	int i, ret = 0;
	ssize_t readlen;
	struct run_as_ret recvret;
	struct run_as_worker *worker;

	pthread_mutex_lock(&worker_lock);
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
	worker->procname = procname;
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

		/* The child has no use for this lock. */
		pthread_mutex_unlock(&worker_lock);
		/* Just close, no shutdown. */
		if (close(worker->sockpair[0])) {
			PERROR("close");
			exit(EXIT_FAILURE);
		}
		worker->sockpair[0] = -1;
		ret = run_as_worker(worker);
		if (lttcomm_close_unix_sock(worker->sockpair[1])) {
			PERROR("close");
			ret = -1;
		}
		worker->sockpair[1] = -1;
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
	pthread_mutex_unlock(&worker_lock);
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
	free(worker);
	pthread_mutex_unlock(&worker_lock);
	return ret;
}

LTTNG_HIDDEN
void run_as_destroy_worker(void)
{
	struct run_as_worker *worker = global_worker;

	DBG("Destroying run_as worker");
	pthread_mutex_lock(&worker_lock);
	if (!worker) {
		goto end;
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
	free(worker);
	global_worker = NULL;
end:
	pthread_mutex_unlock(&worker_lock);
}
