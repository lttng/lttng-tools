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
	struct fs_handle *handle;
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

	stream_fd->handle = handle;
end:
	return stream_fd;
}

struct stream_fd *stream_fd_open(const char *path)
{
	struct stream_fd *stream_fd = NULL;
	int flags = O_RDONLY;
	struct fs_handle *handle;

	handle = fd_tracker_open_fs_handle(the_fd_tracker, path,
			flags, NULL);
	if (!handle) {
		goto end;
	}

	stream_fd = stream_fd_suspendable_create(handle);
	if (!stream_fd) {
		int close_ret;

		close_ret = fs_handle_close(handle);
		if (close_ret) {
			ERR("Failed to close filesystem handle of stream at %s", path);
		}
	}
end:
	return stream_fd;
}

static
struct fs_handle *create_write_fs_handle(const char *path)
{
	struct fs_handle *handle;
	/*
	 * With the session rotation feature on the relay, we might need to seek
	 * and truncate a tracefile, so we need read and write access.
	 */
	int flags = O_RDWR | O_CREAT | O_TRUNC;
	/* Open with 660 mode */
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	handle = fd_tracker_open_fs_handle(the_fd_tracker, path, flags, &mode);
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

	handle = create_write_fs_handle(path);
	if (!handle) {
		goto end;
	}

	stream_fd = stream_fd_suspendable_create(handle);
	if (!stream_fd) {
		int close_ret;

		close_ret = fs_handle_close(handle);
		if (close_ret) {
			ERR("Failed to close filesystem handle of stream at %s", path);
		}
	}
	
end:
	return stream_fd;
}

/*
 * This unlink wrapper allows the fd_tracker to check if any other
 * fs_handle references the stream before unlinking it. If the relay holds
 * this file open, it is essential to unlink it through an fs_handle as this
 * will delay the actual unlink() until all handles have released this file.
 *
 * The file is renamed and unlinked once the last handle to its inode has been
 * released.
 */
static
int unlink_through_handle(const char *path)
{
	int ret = 0, close_ret;
	struct fs_handle *handle;
	/*
	 * Since this operation is only performed to perform the unlink
	 * through the fs_handle and fd-tracker system, the flag is opened
	 * without the O_CREAT. There is no need to perform the unlink if
	 * the file doesn't already exist.
	 */
	int flags = O_RDONLY;

	DBG("Unlinking stream at %s through a filesystem handle", path);
	handle = fd_tracker_open_fs_handle(the_fd_tracker, path, flags, NULL);
	if (!handle) {
		/* There is nothing to do. */
		DBG("File %s does not exist, ignoring unlink", path);
		goto end;
	}

	ret = fs_handle_unlink(handle);
	close_ret = fs_handle_close(handle);
	if (close_ret) {
		ERR("Failed to close handle after performing an unlink operation on a filesystem handle");
	}
end:
	if (ret) {
		DBG("Unlinking stream at %s failed with error code %i", path, ret);
	}
	return ret;
}

int stream_fd_rotate(struct stream_fd *stream_fd, const char *path_name,
		const char *file_name, uint64_t size,
		uint64_t count, uint64_t *new_count)
{
	int ret;
	bool should_unlink;
	char path[PATH_MAX];

	assert(stream_fd);

	utils_stream_file_rotation_get_new_count(count, new_count,
			&should_unlink);

	ret = utils_stream_file_name(path, path_name, file_name,
			size, count, NULL);
	if (ret < 0) {
		goto error;
	}

	ret = fs_handle_close(stream_fd->handle);
	stream_fd->handle = NULL;
	if (ret < 0) {
		PERROR("Closing stream tracefile handle");
		goto error;
	}

	if (should_unlink) {
		ret = unlink_through_handle(path);
		if (ret < 0) {
			goto error;
		}
	}

	ret = utils_stream_file_name(path, path_name, file_name,
			size, new_count ? *new_count : 0, NULL);
	if (ret < 0) {
		goto error;
	}

	stream_fd->handle = create_write_fs_handle(path);
	if (!stream_fd->handle) {
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

	ret = fs_handle_close(sf->handle);
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
	return fs_handle_get_fd(sf->handle);
}

void stream_fd_put_fd(struct stream_fd *sf)
{
	fs_handle_put_fd(sf->handle);
}
