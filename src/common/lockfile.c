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

#ifdef HAVE_FLOCK

#else /* HAVE_FLOCK */

#include <fcntl.h>

int utils_create_lock_file(const char *filepath)
{
	int ret;
	int fd;
	struct flock lock;

	assert(filepath);

	memset(&lock, 0, sizeof(lock));
	fd = open(filepath, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd < 0) {
		PERROR("open lock file %s", filepath);
		fd = -1;
		goto error;
	}

	/*
	 * Attempt to lock the file. If this fails, there is
	 * already a process using the same lock file running
	 * and we should exit.
	 */
	lock.l_whence = SEEK_SET;
	lock.l_type = F_WRLCK;

	ret = fcntl(fd, F_SETLK, &lock);
	if (ret == -1) {
		PERROR("fcntl lock file");
		ERR("Could not get lock file %s, another instance is running.", filepath);
		if (close(fd)) {
			PERROR("close lock file");
		}
		fd = ret;
		goto error;
	}

error:
	return fd;
}

#endif /* HAVE_FLOCK */
