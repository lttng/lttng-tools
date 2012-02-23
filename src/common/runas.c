/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
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

#include <common/error.h>
#include <common/compat/mman.h>
#include <common/compat/clone.h>

#include "runas.h"

#define RUNAS_CHILD_STACK_SIZE	10485760

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

/*
 * Create recursively directory using the FULL path.
 */
static
int _mkdir_recursive(void *_data)
{
	struct run_as_mkdir_data *data = _data;
	const char *path;
	char *p, tmp[PATH_MAX];
	struct stat statbuf;
	mode_t mode;
	size_t len;
	int ret;

	path = data->path;
	mode = data->mode;

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
			ret = stat(tmp, &statbuf);
			if (ret < 0) {
				ret = mkdir(tmp, mode);
				if (ret < 0) {
					if (!(errno == EEXIST)) {
						PERROR("mkdir recursive");
						ret = -errno;
						goto error;
					}
				}
			}
			*p = '/';
		}
	}

	ret = mkdir(tmp, mode);
	if (ret < 0) {
		if (!(errno == EEXIST)) {
			PERROR("mkdir recursive last piece");
			ret = -errno;
		} else {
			ret = 0;
		}
	}

error:
	return ret;
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
int child_run_as(void *_data)
{
	struct run_as_data *data = _data;
	size_t writelen, writeleft, index;
	union {
		int i;
		char c[sizeof(int)];
	} sendret;
	int ret;

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
			perror("setegid");
			return EXIT_FAILURE;
		}
	}
	if (data->uid != geteuid()) {
		ret = seteuid(data->uid);
		if (ret < 0) {
			perror("seteuid");
			return EXIT_FAILURE;
		}
	}
	/*
	 * Also set umask to 0 for mkdir executable bit.
	 */
	umask(0);
	sendret.i = (*data->cmd)(data->data);
	/* send back return value */
	writeleft = sizeof(sendret);
	index = 0;
	do {
		writelen = write(data->retval_pipe, &sendret.c[index],
				writeleft);
		if (writelen < 0) {
			perror("write");
			return EXIT_FAILURE;
		}
		writeleft -= writelen;
		index += writelen;
	} while (writeleft > 0);
	return EXIT_SUCCESS;
}

static
int run_as(int (*cmd)(void *data), void *data, uid_t uid, gid_t gid)
{
	struct run_as_data run_as_data;
	int ret = 0;
	int status;
	pid_t pid;
	int retval_pipe[2];
	ssize_t readlen, readleft, index;
	void *child_stack;
	union {
		int i;
		char c[sizeof(int)];
	} retval;

	/*
	 * If we are non-root, we can only deal with our own uid.
	 */
	if (geteuid() != 0) {
		if (uid != geteuid()) {
			ERR("Client (%d)/Server (%d) UID mismatch (and sessiond is not root)",
				uid, geteuid());
			return -EPERM;
		}
	}

	ret = pipe(retval_pipe);
	if (ret < 0) {
		perror("pipe");
		retval.i = ret;
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
		perror("mmap");
		retval.i = -ENOMEM;
		goto close_pipe;
	}
	/*
	 * Pointing to the middle of the stack to support architectures
	 * where the stack grows up (HPPA).
	 */
	pid = lttng_clone_files(child_run_as, child_stack + (RUNAS_CHILD_STACK_SIZE / 2),
		&run_as_data);
	if (pid < 0) {
		perror("clone");
		retval.i = pid;
		goto unmap_stack;
	}
	/* receive return value */
	readleft = sizeof(retval);
	index = 0;
	do {
		readlen = read(retval_pipe[0], &retval.c[index], readleft);
		if (readlen < 0) {
			perror("read");
			ret = -1;
			break;
		}
		readleft -= readlen;
		index += readlen;
	} while (readleft > 0);

	/*
	 * Parent: wait for child to return, in which case the
	 * shared memory map will have been created.
	 */
	pid = waitpid(pid, &status, 0);
	if (pid < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		perror("wait");
		retval.i = -1;
	}
unmap_stack:
	ret = munmap(child_stack, RUNAS_CHILD_STACK_SIZE);
	if (ret < 0) {
		perror("munmap");
		retval.i = ret;
	}
close_pipe:
	close(retval_pipe[0]);
	close(retval_pipe[1]);
end:
	return retval.i;
}

int run_as_mkdir_recursive(const char *path, mode_t mode, uid_t uid, gid_t gid)
{
	struct run_as_mkdir_data data;

	DBG3("mkdir() recursive %s with mode %d for uid %d and gid %d",
			path, mode, uid, gid);
	data.path = path;
	data.mode = mode;
	return run_as(_mkdir_recursive, &data, uid, gid);
}

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
