/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <common/common.h>

#include "pipe.h"

/*
 * Lock read side of a pipe.
 */
static void lock_read_side(struct lttng_pipe *pipe)
{
	pthread_mutex_lock(&pipe->read_mutex);
}

/*
 * Unlock read side of a pipe.
 */
static void unlock_read_side(struct lttng_pipe *pipe)
{
	pthread_mutex_unlock(&pipe->read_mutex);
}

/*
 * Lock write side of a pipe.
 */
static void lock_write_side(struct lttng_pipe *pipe)
{
	pthread_mutex_lock(&pipe->write_mutex);
}

/*
 * Unlock write side of a pipe.
 */
static void unlock_write_side(struct lttng_pipe *pipe)
{
	pthread_mutex_unlock(&pipe->write_mutex);
}

/*
 * Internal function. Close read side of pipe WITHOUT locking the mutex.
 *
 * Return 0 on success else a negative errno from close(2).
 */
static int _pipe_read_close(struct lttng_pipe *pipe)
{
	int ret, ret_val = 0;

	assert(pipe);

	if (!lttng_pipe_is_read_open(pipe)) {
		goto end;
	}

	do {
		ret = close(pipe->fd[0]);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("close lttng read pipe");
		ret_val = -errno;
	}
	pipe->r_state = LTTNG_PIPE_STATE_CLOSED;

end:
	return ret_val;
}

/*
 * Internal function. Close write side of pipe WITHOUT locking the mutex.
 *
 * Return 0 on success else a negative errno from close(2).
 */
static int _pipe_write_close(struct lttng_pipe *pipe)
{
	int ret, ret_val = 0;

	assert(pipe);

	if (!lttng_pipe_is_write_open(pipe)) {
		goto end;
	}

	do {
		ret = close(pipe->fd[1]);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("close lttng write pipe");
		ret_val = -errno;
	}
	pipe->w_state = LTTNG_PIPE_STATE_CLOSED;

end:
	return ret_val;
}

static struct lttng_pipe *_pipe_create(void)
{
	int ret;
	struct lttng_pipe *p;

	p = zmalloc(sizeof(*p));
	if (!p) {
		PERROR("zmalloc pipe create");
		goto end;
	}
	p->fd[0] = p->fd[1] = -1;

	ret = pthread_mutex_init(&p->read_mutex, NULL);
	if (ret) {
		PERROR("pthread_mutex_init read lock pipe create");
		goto error_destroy;
	}
	ret = pthread_mutex_init(&p->write_mutex, NULL);
	if (ret) {
		PERROR("pthread_mutex_init write lock pipe create");
		goto error_destroy_rmutex;
	}
end:
	return p;
error_destroy_rmutex:
	(void) pthread_mutex_destroy(&p->read_mutex);
error_destroy:
	free(p);
	return NULL;
}

static int _pipe_set_flags(struct lttng_pipe *pipe, int flags)
{
	int i, ret = 0;

	if (!flags) {
		goto end;
	}

	for (i = 0; i < 2; i++) {
		if (flags & O_NONBLOCK) {
			ret = fcntl(pipe->fd[i], F_SETFL, O_NONBLOCK);
			if (ret < 0) {
				PERROR("fcntl lttng pipe %d", flags);
				goto end;
			}
		}
		if (flags & FD_CLOEXEC) {
			ret = fcntl(pipe->fd[i], F_SETFD, FD_CLOEXEC);
			if (ret < 0) {
				PERROR("fcntl lttng pipe %d", flags);
				goto end;
			}
		}
		/*
		 * We only check for O_NONBLOCK or FD_CLOEXEC, if another flag is
		 * needed, we can add it, but for now just make sure we don't make
		 * mistakes with the parameters we pass.
		 */
		if (!(flags & O_NONBLOCK) && !(flags & FD_CLOEXEC)) {
			fprintf(stderr, "Unsupported flag\n");
			ret = -1;
			goto end;
		}
	}
end:
	return ret;
}

/*
 * Open a new lttng pipe and set flags using fcntl().
 *
 * Return a newly allocated lttng pipe on success or else NULL.
 */
LTTNG_HIDDEN
struct lttng_pipe *lttng_pipe_open(int flags)
{
	int ret;
	struct lttng_pipe *p;

	p = _pipe_create();
	if (!p) {
		goto error;
	}

	ret = pipe(p->fd);
	if (ret < 0) {
		PERROR("lttng pipe");
		goto error;
	}
	p->r_state = LTTNG_PIPE_STATE_OPENED;
	p->w_state = LTTNG_PIPE_STATE_OPENED;

	ret = _pipe_set_flags(p, flags);
	if (ret) {
		goto error;
	}

	p->flags = flags;

	return p;
error:
	lttng_pipe_destroy(p);
	return NULL;
}

/*
 * Open a new lttng pipe at path and set flags using fcntl().
 *
 * Return a newly allocated lttng pipe on success or else NULL.
 */
LTTNG_HIDDEN
struct lttng_pipe *lttng_pipe_named_open(const char *path, mode_t mode,
		int flags)
{
	int ret, fd_r, fd_w;
	struct lttng_pipe *pipe;

	pipe = _pipe_create();
	if (!pipe) {
		goto error;
	}

	ret = mkfifo(path, mode);
	if (ret) {
		PERROR("mkfifo");
		goto error;
	}

	fd_r = open(path, O_RDONLY | O_NONBLOCK);
	if (fd_r < 0) {
		PERROR("open fifo");
		goto error;
	}
	pipe->fd[0] = fd_r;
	pipe->r_state = LTTNG_PIPE_STATE_OPENED;

	fd_w = open(path, O_WRONLY | O_NONBLOCK);
	if (fd_w < 0) {
		PERROR("open fifo");
		goto error;
	}
	pipe->fd[1] = fd_w;
	pipe->w_state = LTTNG_PIPE_STATE_OPENED;

	ret = _pipe_set_flags(pipe, flags);
	if (ret) {
		goto error;
	}
	pipe->flags = flags;

	return pipe;
error:
	lttng_pipe_destroy(pipe);
	return NULL;
}

/*
 * Close read side of a lttng pipe.
 *
 * Return 0 on success else a negative value.
 */
LTTNG_HIDDEN
int lttng_pipe_read_close(struct lttng_pipe *pipe)
{
	int ret;

	assert(pipe);

	/* Handle read side first. */
	lock_read_side(pipe);
	ret = _pipe_read_close(pipe);
	unlock_read_side(pipe);

	return ret;
}

/*
 * Close write side of a lttng pipe.
 *
 * Return 0 on success else a negative value.
 */
LTTNG_HIDDEN
int lttng_pipe_write_close(struct lttng_pipe *pipe)
{
	int ret;

	assert(pipe);

	lock_write_side(pipe);
	ret = _pipe_write_close(pipe);
	unlock_write_side(pipe);

	return ret;
}

/*
 * Close both read and write side of a lttng pipe.
 *
 * Return 0 on success else a negative value.
 */
LTTNG_HIDDEN
int lttng_pipe_close(struct lttng_pipe *pipe)
{
	int ret, ret_val = 0;

	assert(pipe);

	ret = lttng_pipe_read_close(pipe);
	if (ret < 0) {
		ret_val = ret;
	}

	ret = lttng_pipe_write_close(pipe);
	if (ret < 0) {
		ret_val = ret;
	}

	return ret_val;
}

/*
 * Close and destroy a lttng pipe object. Finally, pipe is freed.
 */
LTTNG_HIDDEN
void lttng_pipe_destroy(struct lttng_pipe *pipe)
{
	int ret;

	if (!pipe) {
		return;
	}

	/*
	 * Destroy should *never* be called with a locked mutex. These must always
	 * succeed so we unlock them after the close pipe below.
	 */
	ret = pthread_mutex_trylock(&pipe->read_mutex);
	assert(!ret);
	ret = pthread_mutex_trylock(&pipe->write_mutex);
	assert(!ret);

	/* Close pipes WITHOUT trying to lock the pipes. */
	(void) _pipe_read_close(pipe);
	(void) _pipe_write_close(pipe);

	unlock_read_side(pipe);
	unlock_write_side(pipe);

	(void) pthread_mutex_destroy(&pipe->read_mutex);
	(void) pthread_mutex_destroy(&pipe->write_mutex);

	free(pipe);
}

/*
 * Read on a lttng pipe and put the data in buf of at least size count.
 *
 * Return "count" on success. Return < count on error. errno can be used
 * to check the actual error.
 */
LTTNG_HIDDEN
ssize_t lttng_pipe_read(struct lttng_pipe *pipe, void *buf, size_t count)
{
	ssize_t ret;

	assert(pipe);
	assert(buf);

	lock_read_side(pipe);
	if (!lttng_pipe_is_read_open(pipe)) {
		ret = -1;
		errno = EBADF;
		goto error;
	}
	ret = lttng_read(pipe->fd[0], buf, count);
error:
	unlock_read_side(pipe);
	return ret;
}

/*
 * Write on a lttng pipe using the data in buf and size of count.
 *
 * Return "count" on success. Return < count on error. errno can be used
 * to check the actual error.
 */
LTTNG_HIDDEN
ssize_t lttng_pipe_write(struct lttng_pipe *pipe, const void *buf,
		size_t count)
{
	ssize_t ret;

	assert(pipe);
	assert(buf);

	lock_write_side(pipe);
	if (!lttng_pipe_is_write_open(pipe)) {
		ret = -1;
		errno = EBADF;
		goto error;
	}
	ret = lttng_write(pipe->fd[1], buf, count);
error:
	unlock_write_side(pipe);
	return ret;
}

/*
 * Return and release the read end of the pipe.
 *
 * This call transfers the ownership of the read fd of the underlying pipe
 * to the caller if it is still open.
 *
 * Returns the fd of the read end of the pipe, or -1 if it was already closed or
 * released.
 */
LTTNG_HIDDEN
int lttng_pipe_release_readfd(struct lttng_pipe *pipe)
{
	int ret;

	if (!pipe) {
		ret = -1;
		goto end;
	}

	lock_read_side(pipe);
	if (!lttng_pipe_is_read_open(pipe)) {
		ret = -1;
		goto end_unlock;
	}
	ret = pipe->fd[0];
	pipe->fd[0] = -1;
	pipe->r_state = LTTNG_PIPE_STATE_CLOSED;
end_unlock:
	unlock_read_side(pipe);
end:
	return ret;
}

/*
 * Return and release the write end of the pipe.
 *
 * This call transfers the ownership of the write fd of the underlying pipe
 * to the caller if it is still open.
 *
 * Returns the fd of the write end of the pipe, or -1 if it was alwritey closed
 * or released.
 */
LTTNG_HIDDEN
int lttng_pipe_release_writefd(struct lttng_pipe *pipe)
{
	int ret;

	if (!pipe) {
		ret = -1;
		goto end;
	}

	lock_write_side(pipe);
	if (!lttng_pipe_is_write_open(pipe)) {
		ret = -1;
		goto end_unlock;
	}
	ret = pipe->fd[1];
	pipe->fd[1] = -1;
	pipe->w_state = LTTNG_PIPE_STATE_CLOSED;
end_unlock:
	unlock_write_side(pipe);
end:
	return ret;
}
