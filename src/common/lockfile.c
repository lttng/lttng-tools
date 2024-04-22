/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.h>
#include <common/lockfile.h>
#include <common/macros.h>

#include <assert.h>

#include <fcntl.h>

#ifdef HAVE_FLOCK

#include <sys/file.h>

static int lock_file(const char *filepath, int fd)
{
	int ret;

	/*
	 * Attempt to lock the file. If this fails, there is
	 * already a process using the same lock file running
	 * and we should exit.
	 */
	ret = flock(fd, LOCK_EX | LOCK_NB);
	if (ret == -1) {
		/* EWOULDBLOCK are expected if the file is locked: don't spam the logs. */
		if (errno != EWOULDBLOCK) {
			PERROR("Failed to apply lock on lock file: file_path=`%s`", filepath);
		}
	}

	return ret;
}

#else /* HAVE_FLOCK */

static int lock_file(const char *filepath, int fd)
{
	int ret;
	struct flock lock = {};

	lock.l_whence = SEEK_SET;
	lock.l_type = F_WRLCK;

	/*
	 * Attempt to lock the file. If this fails, there is
	 * already a process using the same lock file running
	 * and we should exit.
	 */
	ret = fcntl(fd, F_SETLK, &lock);
	if (ret == -1) {
		/* EAGAIN and EACCESS are expected if the file is locked: don't spam the logs. */
		if (errno != EAGAIN && errno != EACCES) {
			PERROR("Failed to set lock on lock file: file_path=`%s`", filepath);
		}
	}

	return ret;
}

#endif /* HAVE_FLOCK */

LTTNG_HIDDEN
int utils_create_lock_file(const char *filepath)
{
	int ret, fd;

	assert(filepath);

	fd = open(filepath, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		PERROR("Failed to open lock file `%s`", filepath);
		fd = -1;
		goto error;
	}

	/*
	 * Attempt to lock the file. If this fails, there is already a process using the same lock
	 * file running and we should exit.
	 *
	 * lock_file is chosen based on the build configuration, see implementations above.
	 */
	ret = lock_file(filepath, fd);
	if (ret == -1) {
		ERR("Could not get lock file `%s`, another instance is running.", filepath);

		if (close(fd)) {
			PERROR("Failed to close lock file fd: fd=%d", fd);
		}

		fd = ret;
		goto error;
	}

	DBG("Acquired lock file: file_path=`%s`", filepath);

error:
	return fd;
}
