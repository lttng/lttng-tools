/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_PIPE_H
#define LTTNG_PIPE_H

#include <common/macros.hpp>
#include <common/make-unique-wrapper.hpp>

#include <pthread.h>
#include <sys/types.h>

enum lttng_pipe_state {
	LTTNG_PIPE_STATE_OPENED = 1,
	LTTNG_PIPE_STATE_CLOSED = 2,
};

/* Close both side of pipe. */
int lttng_pipe_close(struct lttng_pipe *pipe);

struct lttng_pipe {
	static void _lttng_pipe_close_wrapper(lttng_pipe *pipe)
	{
		lttng_pipe_close(pipe);
	}

	using uptr = std::unique_ptr<
		lttng_pipe,
		lttng::details::create_unique_class<lttng_pipe, _lttng_pipe_close_wrapper>::deleter>;

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
static inline int lttng_pipe_is_read_open(const struct lttng_pipe *pipe)
{
	return pipe->r_state == LTTNG_PIPE_STATE_OPENED ? 1 : 0;
}

/*
 * Return 1 if write side is open else 0.
 */
static inline int lttng_pipe_is_write_open(const struct lttng_pipe *pipe)
{
	return pipe->w_state == LTTNG_PIPE_STATE_OPENED ? 1 : 0;
}

static inline int lttng_pipe_get_readfd(const struct lttng_pipe *pipe)
{
	return pipe->fd[0];
}

static inline int lttng_pipe_get_writefd(const struct lttng_pipe *pipe)
{
	return pipe->fd[1];
}

struct lttng_pipe *lttng_pipe_open(int flags);
struct lttng_pipe *lttng_pipe_named_open(const char *path, mode_t mode, int flags);
int lttng_pipe_write_close(struct lttng_pipe *pipe);
int lttng_pipe_read_close(struct lttng_pipe *pipe);
void lttng_pipe_destroy(struct lttng_pipe *pipe);

ssize_t lttng_pipe_read(struct lttng_pipe *pipe, void *buf, size_t count);
ssize_t lttng_pipe_write(struct lttng_pipe *pipe, const void *buf, size_t count);
/* Returns and releases the read end of the pipe. */
int lttng_pipe_release_readfd(struct lttng_pipe *pipe);
/* Returns and releases the write end of the pipe. */
int lttng_pipe_release_writefd(struct lttng_pipe *pipe);

#endif /* LTTNG_PIPE_H */
