/*
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE

#include <urcu/ref.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <common/common.h>
#include <common/fd-tracker/fd-tracker.h>
#include <common/fd-tracker/utils.h>
#include <common/utils.h>

#include "stream-fd.h"
#include "lttng-relayd.h"

struct stream_fd {
	bool suspendable;
	union {
		/* Suspendable. */
		struct fs_handle *handle;
		/* Unsuspendable. */
		int fd;
	} u;
	struct urcu_ref ref;
};

static struct stream_fd *_stream_fd_alloc(void)
{
	struct stream_fd *sf;

	sf = zmalloc(sizeof(*sf));
	if (!sf) {
		goto end;
	}
	urcu_ref_init(&sf->ref);
end:
	return sf;
}

static struct stream_fd *stream_fd_suspendable_create(struct fs_handle *handle)
{
	struct stream_fd *stream_fd = _stream_fd_alloc();

	if (!stream_fd) {
		goto end;
	}

	stream_fd->suspendable = true;
	stream_fd->u.handle = handle;
end:
	return stream_fd;
}

static struct stream_fd *stream_fd_unsuspendable_create(int fd)
{
	struct stream_fd *stream_fd = _stream_fd_alloc();

	if (!stream_fd) {
		goto end;
	}

	stream_fd->suspendable = false;
	stream_fd->u.fd = fd;
end:
	return stream_fd;
}

static int open_file(void *data, int *out_fd)
{
	int ret;
	const char *path = data;

	ret = open(path, O_RDONLY);
	if (ret < 0) {
		goto end;
	}
	*out_fd = ret;
	ret = 0;
end:
	return ret;
}

/*
 * Stream files are opened (read-only) on the live end of the relayd.
 * In live mode, it is expected that a client is able to consume a
 * complete file even if it is replaced (in file rotation mode).
 *
 * Thus, it is not possible to open those files as suspendable file
 * handles. This means that live clients can keep a large number of
 * open file descriptors. As a work-around, we could create hard links
 * to the files to make the files suspendable. The original file would be
 * replaced, but the viewer's hard-link would ensure that the inode is
 * still available for restoration.
 *
 * The main roadblock to this approach is validating that the trace
 * directory resides in a filesystem that supports hard-links. Otherwise,
 * a cooperative mechanism could allow the viewer end to mark a file as
 * being in use and it could be renamed rather than unlinked by the
 * receiving end.
 */
struct stream_fd *stream_fd_open(const char *path)
{
	int ret, fd;
	struct stream_fd *stream_fd = NULL;

	ret = fd_tracker_open_unsuspendable_fd(the_fd_tracker, &fd,
			(const char **) &path, 1,
			open_file, (void *) path);
	if (ret) {
		goto end;
	}

	stream_fd = stream_fd_unsuspendable_create(fd);
	if (!stream_fd) {
		(void) fd_tracker_close_unsuspendable_fd(the_fd_tracker, &fd, 1,
				fd_tracker_util_close_fd, NULL);
	}
end:
	return stream_fd;
}

static
struct fs_handle *create_fs_handle(const char *path)
{
	struct fs_handle *handle;
	/*
	 * With the session rotation feature on the relay, we might need to seek
	 * and truncate a tracefile, so we need read and write access.
	 */
	int flags = O_RDWR | O_CREAT | O_TRUNC;
	/* Open with 660 mode */
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	handle =  fd_tracker_open_fs_handle(the_fd_tracker, path, flags, &mode);
	if (!handle) {
		ERR("Failed to open fs handle to %s", path);
	}

	return handle;
}

/*
 * Stream file are created by on the consumerd/data-reception end. Those
 * stream fds can be suspended as there is no expectation that the files
 * will be unlinked and then need to be appended-to.
 *
 * Hence, the file descriptors are created as suspendable to allow the
 * fd-tracker to reduce the number of active fds..
 */
struct stream_fd *stream_fd_create(const char *path_name, const char *file_name,
		uint64_t size, uint64_t count, const char *suffix)
{
	struct stream_fd *stream_fd = NULL;
	struct fs_handle *handle;
	int ret;
	char path[PATH_MAX];

	ret = utils_stream_file_name(path, path_name, file_name,
			size, count, suffix);
	if (ret < 0) {
		goto end;
	}

	handle = create_fs_handle(path);
	if (!handle) {
		goto end;
	}

	stream_fd = stream_fd_suspendable_create(handle);
	if (!stream_fd) {
		(void) fs_handle_close(handle);
	}
	
end:
	return stream_fd;
}

int stream_fd_rotate(struct stream_fd *stream_fd, const char *path_name,
		const char *file_name, uint64_t size,
		uint64_t count, uint64_t *new_count)
{
	int ret;
	bool should_unlink;
	char path[PATH_MAX];

	assert(stream_fd);
	assert(stream_fd->suspendable);

	utils_stream_file_rotation_get_new_count(count, new_count,
			&should_unlink);

	ret = utils_stream_file_name(path, path_name, file_name,
			size, count, NULL);
	if (ret < 0) {
		goto error;
	}

	ret = fs_handle_close(stream_fd->u.handle);
	stream_fd->u.handle = NULL;
	if (ret < 0) {
		PERROR("Closing stream tracefile handle");
		goto error;
	}
	
	if (should_unlink) {
		unlink(path);
		if (ret < 0 && errno != ENOENT) {
			goto error;
		}
	}

	ret = utils_stream_file_name(path, path_name, file_name,
			size, new_count ? *new_count : 0, NULL);
	if (ret < 0) {
		goto error;
	}

	stream_fd->u.handle = create_fs_handle(path);
	if (!stream_fd->u.handle) {
		ret = -1;
		goto error;
	}

	ret = 0;

error:
	return ret;
}

void stream_fd_get(struct stream_fd *sf)
{
	urcu_ref_get(&sf->ref);
}

static void stream_fd_release(struct urcu_ref *ref)
{
	struct stream_fd *sf = caa_container_of(ref, struct stream_fd, ref);
	int ret;

	if (sf->suspendable) {
		ret = fs_handle_close(sf->u.handle);
	} else {
		ret = fd_tracker_close_unsuspendable_fd(the_fd_tracker, &sf->u.fd,
				1, fd_tracker_util_close_fd, NULL);
	}
	if (ret) {
		PERROR("Error closing stream handle");
	}
	free(sf);
}

void stream_fd_put(struct stream_fd *sf)
{
	urcu_ref_put(&sf->ref, stream_fd_release);
}

int stream_fd_get_fd(struct stream_fd *sf)
{
	return sf->suspendable ? fs_handle_get_fd(sf->u.handle) : sf->u.fd;
}

void stream_fd_put_fd(struct stream_fd *sf)
{
	if (sf->suspendable) {
		fs_handle_put_fd(sf->u.handle);
	}
}
