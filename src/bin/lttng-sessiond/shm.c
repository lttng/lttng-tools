/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *                       Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <urcu.h>

#include <common/error.h>

#include "benchmark.h"
#include "measures.h"
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

	tracepoint(ust_notify_perms_start);

	/* Default permissions */
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	/* Change owner of the shm path */
	if (global) {
		ret = chown(shm_path, 0, 0);
		if (ret < 0) {
			if (errno != ENOENT) {
				perror("chown wait shm");
				goto error;
			}
		}

		/*
		 * If global session daemon, any application can register so the shm
		 * needs to be set in read-only mode for others.
		 */
		mode |= S_IROTH;
	} else {
		ret = chown(shm_path, getuid(), getgid());
		if (ret < 0) {
			if (errno != ENOENT) {
				perror("chown wait shm");
				goto error;
			}
		}
	}

	/*
	 * Set permissions to the shm even if we did not create the shm.
	 */
	ret = chmod(shm_path, mode);
	if (ret < 0) {
		if (errno != ENOENT) {
			perror("chmod wait shm");
			goto error;
		}
	}

	/*
	 * We're alone in a child process, so we can modify the process-wide
	 * umask.
	 */
	umask(~mode);

	tracepoint(ust_notify_perms_stop);

	tracepoint(ust_notify_shm_start);
	/*
	 * Try creating shm (or get rw access). We don't do an exclusive open,
	 * because we allow other processes to create+ftruncate it concurrently.
	 */
	wait_shm_fd = shm_open(shm_path, O_RDWR | O_CREAT, mode);
	if (wait_shm_fd < 0) {
		perror("shm_open wait shm");
		goto error;
	}

	ret = ftruncate(wait_shm_fd, mmap_size);
	if (ret < 0) {
		perror("ftruncate wait shm");
		exit(EXIT_FAILURE);
	}

	ret = fchmod(wait_shm_fd, mode);
	if (ret < 0) {
		perror("fchmod");
		exit(EXIT_FAILURE);
	}

	tracepoint(ust_notify_shm_stop);

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
	size_t mmap_size = sysconf(_SC_PAGE_SIZE);
	int wait_shm_fd, ret;
	char *wait_shm_mmap;

	wait_shm_fd = get_wait_shm(shm_path, mmap_size, global);
	if (wait_shm_fd < 0) {
		goto error;
	}

	tracepoint(ust_notify_mmap_start);

	wait_shm_mmap = mmap(NULL, mmap_size, PROT_WRITE | PROT_READ,
			MAP_SHARED, wait_shm_fd, 0);

	tracepoint(ust_notify_mmap_stop);
	/* close shm fd immediately after taking the mmap reference */
	ret = close(wait_shm_fd);
	if (ret) {
		perror("Error closing fd");
	}

	if (wait_shm_mmap == MAP_FAILED) {
		DBG("mmap error (can be caused by race with ust).");
		goto error;
	}

	return wait_shm_mmap;

error:
	return NULL;
}
