/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <common/error.h>
#include <common/defaults.h>
#include <common/macros.h>
#include <common/utils.h>

#include "poll.h"

unsigned int poll_max_size;

/*
 * Resize the epoll events structure of the new size.
 *
 * Return 0 on success or else -1 with the current events pointer untouched.
 */
static int resize_poll_event(struct lttng_poll_event *events,
		uint32_t new_size)
{
	struct epoll_event *ptr;

	assert(events);

	ptr = realloc(events->events, new_size * sizeof(*ptr));
	if (ptr == NULL) {
		PERROR("realloc epoll add");
		goto error;
	}
	if (new_size > events->alloc_size) {
		/* Zero newly allocated memory */
		memset(ptr + events->alloc_size, 0,
			(new_size - events->alloc_size) * sizeof(*ptr));
	}
	events->events = ptr;
	events->alloc_size = new_size;

	return 0;

error:
	return -1;
}

/*
 * Create epoll set and allocate returned events structure.
 */
int compat_epoll_create(struct lttng_poll_event *events, int size, int flags)
{
	int ret;

	if (events == NULL || size <= 0) {
		goto error;
	}

	if (!poll_max_size) {
		if (lttng_poll_set_max_size()) {
			goto error;
		}
	}

	/* Don't bust the limit here */
	if (size > poll_max_size) {
		size = poll_max_size;
	}

	ret = compat_glibc_epoll_create(size, flags);
	if (ret < 0) {
		/* At this point, every error is fatal */
		PERROR("epoll_create1");
		goto error;
	}

	events->epfd = ret;

	/* This *must* be freed by using lttng_poll_free() */
	events->events = zmalloc(size * sizeof(struct epoll_event));
	if (events->events == NULL) {
		PERROR("zmalloc epoll set");
		goto error_close;
	}

	events->alloc_size = events->init_size = size;
	events->nb_fd = 0;

	return 0;

error_close:
	ret = close(events->epfd);
	if (ret) {
		PERROR("close");
	}
error:
	return -1;
}

/*
 * Add a fd to the epoll set with requesting events.
 */
int compat_epoll_add(struct lttng_poll_event *events, int fd, uint32_t req_events)
{
	int ret;
	struct epoll_event ev;

	if (events == NULL || events->events == NULL || fd < 0) {
		ERR("Bad compat epoll add arguments");
		goto error;
	}

	/*
	 * Zero struct epoll_event to ensure all representations of its
	 * union are zeroed.
	 */
	memset(&ev, 0, sizeof(ev));
	ev.events = req_events;
	ev.data.fd = fd;

	ret = epoll_ctl(events->epfd, EPOLL_CTL_ADD, fd, &ev);
	if (ret < 0) {
		switch (errno) {
		case EEXIST:
			/* If exist, it's OK. */
			goto end;
		case ENOSPC:
		case EPERM:
			/* Print PERROR and goto end not failing. Show must go on. */
			PERROR("epoll_ctl ADD");
			goto end;
		default:
			PERROR("epoll_ctl ADD fatal");
			goto error;
		}
	}

	events->nb_fd++;

end:
	return 0;

error:
	return -1;
}

/*
 * Remove a fd from the epoll set.
 */
int compat_epoll_del(struct lttng_poll_event *events, int fd)
{
	int ret;

	if (events == NULL || fd < 0 || events->nb_fd == 0) {
		goto error;
	}

	ret = epoll_ctl(events->epfd, EPOLL_CTL_DEL, fd, NULL);
	if (ret < 0) {
		switch (errno) {
		case ENOENT:
		case EPERM:
			/* Print PERROR and goto end not failing. Show must go on. */
			PERROR("epoll_ctl DEL");
			goto end;
		default:
			PERROR("epoll_ctl DEL fatal");
			goto error;
		}
	}

	events->nb_fd--;

end:
	return 0;

error:
	return -1;
}

/*
 * Set an fd's events.
 */
int compat_epoll_mod(struct lttng_poll_event *events, int fd, uint32_t req_events)
{
	int ret;
	struct epoll_event ev;

	if (events == NULL || fd < 0 || events->nb_fd == 0) {
		goto error;
	}

	/*
	 * Zero struct epoll_event to ensure all representations of its
	 * union are zeroed.
	 */
	memset(&ev, 0, sizeof(ev));
	ev.events = req_events;
	ev.data.fd = fd;

	ret = epoll_ctl(events->epfd, EPOLL_CTL_MOD, fd, &ev);
	if (ret < 0) {
		switch (errno) {
		case ENOENT:
		case EPERM:
			/* Print PERROR and goto end not failing. Show must go on. */
			PERROR("epoll_ctl MOD");
			goto end;
		default:
			PERROR("epoll_ctl MOD fatal");
			goto error;
		}
	}

end:
	return 0;

error:
	return -1;
}

/*
 * Wait on epoll set. This is a blocking call of timeout value.
 */
int compat_epoll_wait(struct lttng_poll_event *events, int timeout)
{
	int ret;
	uint32_t new_size;

	if (events == NULL || events->events == NULL) {
		ERR("Wrong arguments in compat_epoll_wait");
		goto error;
	}

	if (events->nb_fd == 0) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Resize if needed before waiting. We could either expand the array or
	 * shrink it down. It's important to note that after this step, we are
	 * ensured that the events argument of the epoll_wait call will be large
	 * enough to hold every possible returned events.
	 */
	new_size = 1U << utils_get_count_order_u32(events->nb_fd);
	if (new_size != events->alloc_size && new_size >= events->init_size) {
		ret = resize_poll_event(events, new_size);
		if (ret < 0) {
			/* ENOMEM problem at this point. */
			goto error;
		}
	}

	do {
		ret = epoll_wait(events->epfd, events->events, events->nb_fd, timeout);
	} while (ret == -1 && errno == EINTR);
	if (ret < 0) {
		/* At this point, every error is fatal */
		PERROR("epoll_wait");
		goto error;
	}

	/*
	 * Since the returned events are set sequentially in the "events" structure
	 * we only need to return the epoll_wait value and iterate over it.
	 */
	return ret;

error:
	return -1;
}

/*
 * Setup poll set maximum size.
 */
int compat_epoll_set_max_size(void)
{
	int ret, fd, retval = 0;
	ssize_t size_ret;
	char buf[64];

	fd = open(COMPAT_EPOLL_PROC_PATH, O_RDONLY);
	if (fd < 0) {
		/*
		 * Failing on opening [1] is not an error per see. [1] was
		 * introduced in Linux 2.6.28 but epoll is available since
		 * 2.5.44. Hence, goto end and set a default value without
		 * setting an error return value.
		 *
		 * [1] /proc/sys/fs/epoll/max_user_watches
		 */
		retval = 0;
		goto end;
	}

	size_ret = lttng_read(fd, buf, sizeof(buf));
	/*
	 * Allow reading a file smaller than buf, but keep space for
	 * final \0.
	 */
	if (size_ret < 0 || size_ret >= sizeof(buf)) {
		PERROR("read set max size");
		retval = -1;
		goto end_read;
	}
	buf[size_ret] = '\0';
	poll_max_size = atoi(buf);
end_read:
	ret = close(fd);
	if (ret) {
		PERROR("close");
	}
end:
	if (!poll_max_size) {
		poll_max_size = DEFAULT_POLL_SIZE;
	}
	DBG("epoll set max size is %d", poll_max_size);
	return retval;
}
