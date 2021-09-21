/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/fs-handle-internal.h>
#include <common/fs-handle.h>
#include <common/readwrite.h>

int fs_handle_get_fd(struct fs_handle *handle)
{
	return handle->get_fd(handle);
}

void fs_handle_put_fd(struct fs_handle *handle)
{
	return handle->put_fd(handle);
}

int fs_handle_unlink(struct fs_handle *handle)
{
	return handle->unlink(handle);
}

int fs_handle_close(struct fs_handle *handle)
{
	return handle->close(handle);
}

ssize_t fs_handle_read(struct fs_handle *handle, void *buf, size_t count)
{
	ssize_t ret;
	const int fd = fs_handle_get_fd(handle);

	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = lttng_read(fd, buf, count);
	fs_handle_put_fd(handle);
end:
	return ret;
}

ssize_t fs_handle_write(struct fs_handle *handle, const void *buf, size_t count)
{
	ssize_t ret;
	const int fd = fs_handle_get_fd(handle);

	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = lttng_write(fd, buf, count);
	fs_handle_put_fd(handle);
end:
	return ret;
}

int fs_handle_truncate(struct fs_handle *handle, off_t offset)
{
	int ret;
	const int fd = fs_handle_get_fd(handle);

	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = ftruncate(fd, offset);
	fs_handle_put_fd(handle);
end:
	return ret;
}

off_t fs_handle_seek(struct fs_handle *handle, off_t offset, int whence)
{
	off_t ret;
	const int fd = fs_handle_get_fd(handle);

	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = lseek(fd, offset, whence);
	fs_handle_put_fd(handle);
end:
	return ret;
}
