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

#define _GNU_SOURCE
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
#include <sys/signal.h>

#include <common/common.h>
#include <common/utils.h>
#include <common/compat/mman.h>
#include <common/compat/clone.h>
#include <common/compat/getenv.h>

#include "runas.h"

#define RUNAS_CHILD_STACK_SIZE	10485760

#ifndef MAP_STACK
#define MAP_STACK		0
#endif

#ifdef __FreeBSD__
/* FreeBSD MAP_STACK always return -ENOMEM */
#define LTTNG_MAP_STACK		0
#else
#define LTTNG_MAP_STACK		MAP_STACK
#endif

#ifndef MAP_GROWSDOWN
#define MAP_GROWSDOWN		0
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS		MAP_ANON
#endif

struct run_as_data {
	int (*cmd)(void *data);
	void *data;
	uid_t uid;
	gid_t gid;
	int retval_pipe;
};

struct run_as_mkdir_data {
	const char *path;
	mode_t mode;
};

struct run_as_open_data {
	const char *path;
	int flags;
	mode_t mode;
};

struct run_as_unlink_data {
	const char *path;
};

struct run_as_recursive_rmdir_data {
	const char *path;
};

struct run_as_ret {
	int ret;
	int _errno;
};

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
int _mkdir_recursive(void *_data)
{
	struct run_as_mkdir_data *data = _data;
	const char *path;
	mode_t mode;

	path = data->path;
	mode = data->mode;

	return utils_mkdir_recursive(path, mode);
}

static
int _mkdir(void *_data)
{
	struct run_as_mkdir_data *data = _data;

	return mkdir(data->path, data->mode);
}

static
int _open(void *_data)
{
	struct run_as_open_data *data = _data;

	return open(data->path, data->flags, data->mode);
}

static
int _unlink(void *_data)
{
	struct run_as_unlink_data *data = _data;

	return unlink(data->path);
}

static
int _recursive_rmdir(void *_data)
{
	struct run_as_recursive_rmdir_data *data = _data;

	return utils_recursive_rmdir(data->path);
}

static
int child_run_as(void *_data)
{
	int ret;
	struct run_as_data *data = _data;
	ssize_t writelen;
	struct run_as_ret sendret;

	/*
	 * Child: it is safe to drop egid and euid while sharing the
	 * file descriptors with the parent process, since we do not
	 * drop "uid": therefore, the user we are dropping egid/euid to
	 * cannot attach to this process with, e.g. ptrace, nor map this
	 * process memory.
	 */
	if (data->gid != getegid()) {
		ret = setegid(data->gid);
		if (ret < 0) {
			PERROR("setegid");
			goto write_return;
		}
	}
	if (data->uid != geteuid()) {
		ret = seteuid(data->uid);
		if (ret < 0) {
			PERROR("seteuid");
			goto write_return;
		}
	}
	/*
	 * Also set umask to 0 for mkdir executable bit.
	 */
	umask(0);
	ret = (*data->cmd)(data->data);

write_return:
	sendret.ret = ret;
	sendret._errno = errno;
	/* send back return value */
	writelen = lttng_write(data->retval_pipe, &sendret, sizeof(sendret));
	if (writelen < sizeof(sendret)) {
		PERROR("lttng_write error");
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}

static
int run_as_clone(int (*cmd)(void *data), void *data, uid_t uid, gid_t gid)
{
	struct run_as_data run_as_data;
	int ret = 0;
	ssize_t readlen;
	int status;
	pid_t pid;
	int retval_pipe[2];
	void *child_stack;
	struct run_as_ret recvret;

	/*
	 * If we are non-root, we can only deal with our own uid.
	 */
	if (geteuid() != 0) {
		if (uid != geteuid()) {
			recvret.ret = -1;
			recvret._errno = EPERM;
			ERR("Client (%d)/Server (%d) UID mismatch (and sessiond is not root)",
				uid, geteuid());
			goto end;
		}
	}

	ret = pipe(retval_pipe);
	if (ret < 0) {
		recvret.ret = -1;
		recvret._errno = errno;
		PERROR("pipe");
		goto end;
	}
	run_as_data.data = data;
	run_as_data.cmd = cmd;
	run_as_data.uid = uid;
	run_as_data.gid = gid;
	run_as_data.retval_pipe = retval_pipe[1];	/* write end */
	child_stack = mmap(NULL, RUNAS_CHILD_STACK_SIZE,
		PROT_WRITE | PROT_READ,
		MAP_PRIVATE | MAP_GROWSDOWN | MAP_ANONYMOUS | LTTNG_MAP_STACK,
		-1, 0);
	if (child_stack == MAP_FAILED) {
		recvret.ret = -1;
		recvret._errno = ENOMEM;
		PERROR("mmap");
		goto close_pipe;
	}
	/*
	 * Pointing to the middle of the stack to support architectures
	 * where the stack grows up (HPPA).
	 */
	pid = lttng_clone_files(child_run_as, child_stack + (RUNAS_CHILD_STACK_SIZE / 2),
		&run_as_data);
	if (pid < 0) {
		recvret.ret = -1;
		recvret._errno = errno;
		PERROR("clone");
		goto unmap_stack;
	}
	/* receive return value */
	readlen = lttng_read(retval_pipe[0], &recvret, sizeof(recvret));
	if (readlen < sizeof(recvret)) {
		recvret.ret = -1;
		recvret._errno = errno;
	}

	/*
	 * Parent: wait for child to return, in which case the
	 * shared memory map will have been created.
	 */
	pid = waitpid(pid, &status, 0);
	if (pid < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		recvret.ret = -1;
		recvret._errno = errno;
		PERROR("wait");
	}
unmap_stack:
	ret = munmap(child_stack, RUNAS_CHILD_STACK_SIZE);
	if (ret < 0) {
		recvret.ret = -1;
		recvret._errno = errno;
		PERROR("munmap");
	}
close_pipe:
	ret = close(retval_pipe[0]);
	if (ret) {
		recvret.ret = -1;
		recvret._errno = errno;
		PERROR("close");
	}
	ret = close(retval_pipe[1]);
	if (ret) {
		recvret.ret = -1;
		recvret._errno = errno;
		PERROR("close");
	}
end:
	errno = recvret._errno;
	return recvret.ret;
}

/*
 * To be used on setups where gdb has issues debugging programs using
 * clone/rfork. Note that this is for debuging ONLY, and should not be
 * considered secure.
 */
static
int run_as_noclone(int (*cmd)(void *data), void *data, uid_t uid, gid_t gid)
{
	int ret, saved_errno;
	mode_t old_mask;

	old_mask = umask(0);
	ret = cmd(data);
	saved_errno = errno;
	umask(old_mask);
	errno = saved_errno;

	return ret;
}

static
int run_as(int (*cmd)(void *data), void *data, uid_t uid, gid_t gid)
{
	if (use_clone()) {
		int ret;

		DBG("Using run_as_clone");
		pthread_mutex_lock(&lttng_libc_state_lock);
		ret = run_as_clone(cmd, data, uid, gid);
		pthread_mutex_unlock(&lttng_libc_state_lock);
		return ret;
	} else {
		DBG("Using run_as_noclone");
		return run_as_noclone(cmd, data, uid, gid);
	}
}

LTTNG_HIDDEN
int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	struct run_as_mkdir_data data;

	DBG3("mkdir() recursive %s with mode %d for uid %d and gid %d",
			path, mode, uid, gid);
	data.path = path;
	data.mode = mode;
	return run_as(_mkdir_recursive, &data, uid, gid);
}

LTTNG_HIDDEN
int run_as_mkdir(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	struct run_as_mkdir_data data;

	DBG3("mkdir() %s with mode %d for uid %d and gid %d",
			path, mode, uid, gid);
	data.path = path;
	data.mode = mode;
	return run_as(_mkdir, &data, uid, gid);
}

/*
 * Note: open_run_as is currently not working. We'd need to pass the fd
 * opened in the child to the parent.
 */
LTTNG_HIDDEN
int run_as_open(const char *path, int flags, mode_t mode, uid_t uid, gid_t gid)
{
	struct run_as_open_data data;

	DBG3("open() %s with flags %X mode %d for uid %d and gid %d",
			path, flags, mode, uid, gid);
	data.path = path;
	data.flags = flags;
	data.mode = mode;
	return run_as(_open, &data, uid, gid);
}

LTTNG_HIDDEN
int run_as_unlink(const char *path, uid_t uid, gid_t gid)
{
	struct run_as_unlink_data data;

	DBG3("unlink() %s with for uid %d and gid %d",
			path, uid, gid);
	data.path = path;
	return run_as(_unlink, &data, uid, gid);
}

LTTNG_HIDDEN
int run_as_recursive_rmdir(const char *path, uid_t uid, gid_t gid)
{
	struct run_as_recursive_rmdir_data data;

	DBG3("recursive_rmdir() %s with for uid %d and gid %d",
			path, uid, gid);
	data.path = path;
	return run_as(_recursive_rmdir, &data, uid, gid);
}
