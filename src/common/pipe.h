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

#ifndef LTTNG_PIPE_H
#define LTTNG_PIPE_H

#include <pthread.h>
#include <common/macros.h>
#include <sys/types.h>

enum lttng_pipe_state {
	LTTNG_PIPE_STATE_OPENED = 1,
	LTTNG_PIPE_STATE_CLOSED = 2,
};

struct lttng_pipe {
	/* Read: 0, Write: 1. */
	int fd[2];
	/*
	 * Flags of the pipe once opened. pipe(2) specifies either O_NONBLOCK or
	 * O_CLOEXEC can be used. Flags are set using fcntl(2) call.
	 */
	int flags;

	/*
	 * These states are protected by the operation mutex below.
	 */
	enum lttng_pipe_state r_state;
	enum lttng_pipe_state w_state;

	/* Held for each read(2) operation. */
	pthread_mutex_t read_mutex;
	/* Held for each write(2) operation. */
	pthread_mutex_t write_mutex;
};

/*
 * Return 1 if read side is open else 0.
 */
static inline int lttng_pipe_is_read_open(struct lttng_pipe *pipe)
{
	return pipe->r_state == LTTNG_PIPE_STATE_OPENED ? 1 : 0;
}

/*
 * Return 1 if write side is open else 0.
 */
static inline int lttng_pipe_is_write_open(struct lttng_pipe *pipe)
{
	return pipe->w_state == LTTNG_PIPE_STATE_OPENED ? 1 : 0;
}

static inline int lttng_pipe_get_readfd(struct lttng_pipe *pipe)
{
	return pipe->fd[0];
}

static inline int lttng_pipe_get_writefd(struct lttng_pipe *pipe)
{
	return pipe->fd[1];
}

LTTNG_HIDDEN
struct lttng_pipe *lttng_pipe_open(int flags);
LTTNG_HIDDEN
struct lttng_pipe *lttng_pipe_named_open(const char *path, mode_t mode,
		int flags);
LTTNG_HIDDEN
int lttng_pipe_write_close(struct lttng_pipe *pipe);
LTTNG_HIDDEN
int lttng_pipe_read_close(struct lttng_pipe *pipe);
/* Close both side of pipe. */
LTTNG_HIDDEN
int lttng_pipe_close(struct lttng_pipe *pipe);
LTTNG_HIDDEN
void lttng_pipe_destroy(struct lttng_pipe *pipe);

LTTNG_HIDDEN
ssize_t lttng_pipe_read(struct lttng_pipe *pipe, void *buf, size_t count);
LTTNG_HIDDEN
ssize_t lttng_pipe_write(struct lttng_pipe *pipe, const void *buf,
		size_t count);
/* Returns and releases the read end of the pipe. */
LTTNG_HIDDEN
int lttng_pipe_release_readfd(struct lttng_pipe *pipe);
/* Returns and releases the write end of the pipe. */
LTTNG_HIDDEN
int lttng_pipe_release_writefd(struct lttng_pipe *pipe);

#endif /* LTTNG_PIPE_H */
