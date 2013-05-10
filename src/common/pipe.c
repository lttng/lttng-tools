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

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

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


/*
 * Open a new lttng pipe and set flags using fcntl().
 *
 * Return a newly allocated lttng pipe on success or else NULL.
 */
struct lttng_pipe *lttng_pipe_open(int flags)
{
	int ret;
	struct lttng_pipe *p;

	p = zmalloc(sizeof(*p));
	if (!p) {
		PERROR("zmalloc pipe open");
		goto error;
	}

	ret = pipe(p->fd);
	if (ret < 0) {
		PERROR("lttng pipe");
		goto error;
	}

	if (flags) {
		int i;

		for (i = 0; i < 2; i++) {
			ret = fcntl(p->fd[i], F_SETFD, flags);
			if (ret < 0) {
				PERROR("fcntl lttng pipe %d", flags);
				goto error;
			}
		}
	}

	pthread_mutex_init(&p->read_mutex, NULL);
	pthread_mutex_init(&p->write_mutex, NULL);
	p->r_state = LTTNG_PIPE_STATE_OPENED;
	p->w_state = LTTNG_PIPE_STATE_OPENED;
	p->flags = flags;

	return p;

error:
	lttng_pipe_destroy(p);
	return NULL;
}

/*
 * Close read side of a lttng pipe.
 *
 * Return 0 on success else a negative value.
 */
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
 * Return 0 on success or else a negative errno message from read(2).
 */
ssize_t lttng_pipe_read(struct lttng_pipe *pipe, void *buf, size_t count)
{
	ssize_t ret, read_len, read_left, index;

	assert(pipe);
	assert(buf);

	lock_read_side(pipe);

	if (!lttng_pipe_is_read_open(pipe)) {
		ret = -EBADF;
		goto error;
	}

	read_left = count;
	index = 0;
	do {
		read_len = read(pipe->fd[0], buf + index, read_left);
		if (read_len < 0) {
			ret = -errno;
			if (errno == EINTR) {
				/* Read again. */
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * Return the number of bytes read up to this point if any.
				 */
				if (index) {
					ret = index;
				}
				goto error;
			} else {
				PERROR("lttng pipe read");
				goto error;
			}
		}
		read_left -= read_len;
		index += read_len;
	} while (read_left > 0);

	/* Everything went fine. */
	ret = index;

error:
	unlock_read_side(pipe);
	return ret;
}

/*
 * Write on a lttng pipe using the data in buf and size of count.
 *
 * Return 0 on success or else a negative errno message from write(2).
 */
ssize_t lttng_pipe_write(struct lttng_pipe *pipe, const void *buf,
		size_t count)
{
	ssize_t ret, write_len, write_left, index;

	assert(pipe);
	assert(buf);

	lock_write_side(pipe);

	if (!lttng_pipe_is_write_open(pipe)) {
		ret = -EBADF;
		goto error;
	}

	write_left = count;
	index = 0;
	do {
		write_len = write(pipe->fd[1], buf + index, write_left);
		if (write_len < 0) {
			ret = -errno;
			if (errno == EINTR) {
				/* Read again. */
				continue;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * Return the number of bytes read up to this point if any.
				 */
				if (index) {
					ret = index;
				}
				goto error;
			} else {
				PERROR("lttng pipe write");
				goto error;
			}
		}
		write_left -= write_len;
		index += write_len;
	} while (write_left > 0);

	/* Everything went fine. */
	ret = index;

error:
	unlock_write_side(pipe);
	return ret;
}
