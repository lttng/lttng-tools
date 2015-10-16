/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *                       Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <urcu.h>

#include <common/error.h>

#include "shm.h"

/*
 * Using fork to set umask in the child process (not multi-thread safe). We
 * deal with the shm_open vs ftruncate race (happening when the sessiond owns
 * the shm and does not let everybody modify it, to ensure safety against
 * shm_unlink) by simply letting the mmap fail and retrying after a few
 * seconds. For global shm, everybody has rw access to it until the sessiond
 * starts.
 */
static int get_wait_shm(char *shm_path, size_t mmap_size, int global)
{
	int wait_shm_fd, ret;
	mode_t mode;

	assert(shm_path);

	/* Default permissions */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	/*
	 * Change owner of the shm path.
	 */
	if (global) {
		/*
		 * If global session daemon, any application can
		 * register. Make it initially writeable so applications
		 * registering concurrently can do ftruncate() by
		 * themselves.
		 */
		mode |= S_IROTH | S_IWOTH;
	}

	/*
	 * We're alone in a child process, so we can modify the process-wide
	 * umask.
	 */
	umask(~mode);

	/*
	 * Try creating shm (or get rw access). We don't do an exclusive open,
	 * because we allow other processes to create+ftruncate it concurrently.
	 */
	wait_shm_fd = shm_open(shm_path, O_RDWR | O_CREAT, mode);
	if (wait_shm_fd < 0) {
		PERROR("shm_open wait shm");
		goto error;
	}

	ret = ftruncate(wait_shm_fd, mmap_size);
	if (ret < 0) {
		PERROR("ftruncate wait shm");
		exit(EXIT_FAILURE);
	}

#ifndef __FreeBSD__
	if (global) {
		ret = fchown(wait_shm_fd, 0, 0);
		if (ret < 0) {
			PERROR("fchown");
			exit(EXIT_FAILURE);
		}
		/*
		 * If global session daemon, any application can
		 * register so the shm needs to be set in read-only mode
		 * for others.
		 */
		mode &= ~S_IWOTH;
		ret = fchmod(wait_shm_fd, mode);
		if (ret < 0) {
			PERROR("fchmod");
			exit(EXIT_FAILURE);
		}
	} else {
		ret = fchown(wait_shm_fd, getuid(), getgid());
		if (ret < 0) {
			PERROR("fchown");
			exit(EXIT_FAILURE);
		}
	}
#else
#warning "FreeBSD does not support setting file mode on shm FD."
#endif

	DBG("Got the wait shm fd %d", wait_shm_fd);

	return wait_shm_fd;

error:
	DBG("Failing to get the wait shm fd");

	return -1;
}

/*
 * Return the wait shm mmap for UST application notification. The global
 * variable is used to indicate if the the session daemon is global
 * (root:tracing) or running with an unprivileged user.
 *
 * This returned value is used by futex_wait_update() in futex.c to WAKE all
 * waiters which are UST application waiting for a session daemon.
 */
char *shm_ust_get_mmap(char *shm_path, int global)
{
	size_t mmap_size;
	int wait_shm_fd, ret;
	char *wait_shm_mmap;
	long sys_page_size;

	assert(shm_path);

	sys_page_size = sysconf(_SC_PAGE_SIZE);
	if (sys_page_size < 0) {
		PERROR("sysconf PAGE_SIZE");
		goto error;
	}
	mmap_size = sys_page_size;

	wait_shm_fd = get_wait_shm(shm_path, mmap_size, global);
	if (wait_shm_fd < 0) {
		goto error;
	}

	wait_shm_mmap = mmap(NULL, mmap_size, PROT_WRITE | PROT_READ,
			MAP_SHARED, wait_shm_fd, 0);

	/* close shm fd immediately after taking the mmap reference */
	ret = close(wait_shm_fd);
	if (ret) {
		PERROR("Error closing fd");
	}

	if (wait_shm_mmap == MAP_FAILED) {
		DBG("mmap error (can be caused by race with ust).");
		goto error;
	}

	return wait_shm_mmap;

error:
	return NULL;
}
