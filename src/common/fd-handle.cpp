/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <unistd.h>
#include <urcu/ref.h>

#include "fd-handle.hpp"
#include <common/error.hpp>

struct fd_handle {
	struct urcu_ref ref;
	int fd;
};

static void fd_handle_release(struct urcu_ref *ref)
{
	int ret;
	struct fd_handle *handle = container_of(ref, struct fd_handle, ref);

	LTTNG_ASSERT(handle->fd >= 0);
	ret = close(handle->fd);
	if (ret == -1) {
		PERROR("Failed to close file descriptor of fd_handle upon release: fd = %d",
				handle->fd);
	}

	free(handle);
}

struct fd_handle *fd_handle_create(int fd)
{
	struct fd_handle *handle = NULL;

	if (fd < 0) {
		ERR("Attempted to create an fd_handle from an invalid file descriptor: fd = %d",
				fd);
		goto end;
	}

	handle = zmalloc<fd_handle>();
	if (!handle) {
		PERROR("Failed to allocate fd_handle");
		goto end;
	}

	urcu_ref_init(&handle->ref);
	handle->fd = fd;

end:
	return handle;
}

void fd_handle_get(struct fd_handle *handle)
{
	if (!handle) {
		return;
	}

	urcu_ref_get(&handle->ref);
}

void fd_handle_put(struct fd_handle *handle)
{
	if (!handle) {
		return;
	}

	urcu_ref_put(&handle->ref, fd_handle_release);
}

int fd_handle_get_fd(struct fd_handle *handle)
{
	LTTNG_ASSERT(handle);
	return handle->fd;
}

struct fd_handle *fd_handle_copy(const struct fd_handle *handle)
{
	struct fd_handle *new_handle = NULL;
	const int new_fd = dup(handle->fd);

	if (new_fd < 0) {
		PERROR("Failed to duplicate file descriptor while copying fd_handle: fd = %d", handle->fd);
		goto end;
	}

	new_handle = fd_handle_create(new_fd);
end:
	return new_handle;
}
