/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "shm.hpp"

#include <common/error.hpp>

#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <urcu.h>

static int wait_shm_open(const char *wait_shm_path, int flags, mode_t mode, bool wait_shm_is_file)
{
	if (wait_shm_is_file) {
		return open(wait_shm_path, flags, mode);
	} else {
		return shm_open(wait_shm_path, flags, mode);
	}
}

/*
 * We deal with the shm_open vs ftruncate race (happening when the sessiond owns
 * the shm and does not let everybody modify it, to ensure safety against
 * shm_unlink) by simply letting the mmap fail and retrying after a few
 * seconds. For global shm, everybody has rw access to it until the sessiond
 * starts.
 */
static int get_wait_shm(char *shm_path, bool wait_shm_is_file, size_t mmap_size, int global)
{
	int wait_shm_fd, ret;
	mode_t mode, old_mode;

	LTTNG_ASSERT(shm_path);

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

	old_mode = umask(~mode);

	/*
	 * Try creating shm (or get rw access). We don't do an exclusive open,
	 * because we allow other processes to create+ftruncate it concurrently.
	 *
	 * A sysctl, fs.protected_regular may prevent the session daemon from
	 * opening a previously created shm when the O_CREAT flag is provided.
	 * Systemd enables this ABI-breaking change by default since v241.
	 *
	 * First, attempt to use the create-or-open semantic that is
	 * desired here. If this fails with EACCES, work around this broken
	 * behaviour and attempt to open the shm without the O_CREAT flag.
	 *
	 * The two attempts are made in this order since applications are
	 * expected to race with the session daemon to create this shm.
	 * Attempting an shm_open() without the O_CREAT flag first could fail
	 * because the file doesn't exist. It could then be created by an
	 * application, which would cause a second try with the O_CREAT flag to
	 * fail with EACCES.
	 *
	 * Note that this introduces a new failure mode where a user could
	 * launch an application (creating the shm) and unlink the shm while
	 * the session daemon is launching, causing the second attempt
	 * to fail. This is not recovered-from as unlinking the shm will
	 * prevent userspace tracing from succeeding anyhow: the sessiond would
	 * use a now-unlinked shm, while the next application would create
	 * a new named shm.
	 */
	wait_shm_fd = wait_shm_open(shm_path, O_RDWR | O_CREAT, mode, wait_shm_is_file);
	if (wait_shm_fd < 0) {
		if (errno == EACCES) {
			/* Work around sysctl fs.protected_regular. */
			DBG("shm_open of %s returned EACCES, this may be caused "
			    "by the fs.protected_regular sysctl. "
			    "Attempting to open the shm without "
			    "creating it.",
			    shm_path);
			wait_shm_fd = wait_shm_open(shm_path, O_RDWR, mode, wait_shm_is_file);
		}
		if (wait_shm_fd < 0) {
			PERROR("Failed to open \"wait\" shared memory object: path = '%s'",
			       shm_path);
			goto error;
		}
	}

	ret = ftruncate(wait_shm_fd, mmap_size);
	if (ret < 0) {
		PERROR("Failed to truncate \"wait\" shared memory object: fd = %d, size = %zu",
		       wait_shm_fd,
		       mmap_size);
		goto error;
	}

	if (global) {
		ret = fchown(wait_shm_fd, 0, 0);
		if (ret < 0) {
			PERROR("Failed to set ownership of \"wait\" shared memory object: fd = %d, owner = 0, group = 0",
			       wait_shm_fd);
			goto error;
		}
		/*
		 * If global session daemon, any application can
		 * register so the shm needs to be set in read-only mode
		 * for others.
		 */
		mode &= ~S_IWOTH;
		ret = fchmod(wait_shm_fd, mode);
		if (ret < 0) {
			PERROR("Failed to set the mode of the \"wait\" shared memory object: fd = %d, mode = %d",
			       wait_shm_fd,
			       mode);
			goto error;
		}
	} else {
		ret = fchown(wait_shm_fd, getuid(), getgid());
		if (ret < 0) {
			PERROR("Failed to set ownership of \"wait\" shared memory object: fd = %d, owner = %d, group = %d",
			       wait_shm_fd,
			       getuid(),
			       getgid());
			goto error;
		}
	}

	DBG("Wait shared memory file descriptor created successfully: path = '%s', mmap_size = %zu, global = %s, fd = %d",
	    shm_path,
	    mmap_size,
	    global ? "true" : "false",
	    wait_shm_fd);

end:
	(void) umask(old_mode);
	return wait_shm_fd;

error:
	DBG("Failing to get the wait shm fd");
	if (wait_shm_fd >= 0) {
		if (close(wait_shm_fd)) {
			PERROR("Failed to close wait shm file descriptor during error handling");
		}
	}

	wait_shm_fd = -1;
	goto end;
}

/*
 * Return the wait shm mmap for UST application notification. The global
 * variable is used to indicate if the the session daemon is global
 * (root:tracing) or running with an unprivileged user.
 *
 * This returned value is used by futex_wait_update() in futex.c to WAKE all
 * waiters which are UST application waiting for a session daemon.
 */
char *shm_ust_get_mmap(char *shm_path, bool wait_shm_is_file, int global)
{
	size_t mmap_size;
	int wait_shm_fd, ret;
	char *wait_shm_mmap;
	long sys_page_size;

	LTTNG_ASSERT(shm_path);

	sys_page_size = sysconf(_SC_PAGE_SIZE);
	if (sys_page_size < 0) {
		PERROR("Failed to get PAGE_SIZE of system");
		goto error;
	}
	mmap_size = sys_page_size;

	wait_shm_fd = get_wait_shm(shm_path, wait_shm_is_file, mmap_size, global);
	if (wait_shm_fd < 0) {
		goto error;
	}

	wait_shm_mmap = (char *) mmap(
		nullptr, mmap_size, PROT_WRITE | PROT_READ, MAP_SHARED, wait_shm_fd, 0);

	/* close shm fd immediately after taking the mmap reference */
	ret = close(wait_shm_fd);
	if (ret) {
		PERROR("Failed to close \"wait\" shared memory object file descriptor: fd = %d",
		       wait_shm_fd);
	}

	if (wait_shm_mmap == MAP_FAILED) {
		DBG("Failed to mmap the \"wait\" shareed memory object (can be caused by race with ust): path = '%s', global = %s",
		    shm_path,
		    global ? "true" : "false");
		goto error;
	}

	return wait_shm_mmap;

error:
	return nullptr;
}

/*
 * shm_create_anonymous is never called concurrently within a process.
 */
int shm_create_anonymous(const char *owner_name)
{
	char tmp_name[NAME_MAX];
	int shmfd, ret;

	ret = snprintf(tmp_name, NAME_MAX, "/shm-%s-%d", owner_name, getpid());
	if (ret < 0) {
		PERROR("Failed to format shm path: owner_name = '%s', pid = %d",
		       owner_name,
		       getpid());
		return -1;
	}

	/*
	 * Allocate shm, and immediately unlink its shm oject, keeping only the
	 * file descriptor as a reference to the object.
	 */
	shmfd = shm_open(tmp_name, O_CREAT | O_EXCL | O_RDWR, 0700);
	if (shmfd < 0) {
		PERROR("Failed to open shared memory object: path = '%s'", tmp_name);
		goto error_shm_open;
	}

	ret = shm_unlink(tmp_name);
	if (ret < 0 && errno != ENOENT) {
		PERROR("Failed to unlink shared memory object: path = '%s'", tmp_name);
		goto error_shm_release;
	}

	return shmfd;

error_shm_release:
	ret = close(shmfd);
	if (ret) {
		PERROR("Failed to close shared memory object file descriptor: fd = %d, path = '%s'",
		       shmfd,
		       tmp_name);
	}
error_shm_open:
	return -1;
}
