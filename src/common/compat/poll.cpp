/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2019 Yannick Lamarre <ylamarre@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <stdlib.h>
#include <stdbool.h>

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/utils.hpp>

#include "poll.hpp"

#ifdef HAVE_EPOLL

#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Maximum number of fd we can monitor.
 *
 * For epoll(7), /proc/sys/fs/epoll/max_user_watches (since Linux 2.6.28) will
 * be used for the maximum size of the poll set. If this interface is not
 * available, according to the manpage, the max_user_watches value is 1/25 (4%)
 * of the available low memory divided by the registration cost in bytes which
 * is 90 bytes on a 32-bit kernel and 160 bytes on a 64-bit kernel.
 *
 */
static unsigned int poll_max_size;

/*
 * Resize the epoll events structure of the new size.
 *
 * Return 0 on success or else -1 with the current events pointer untouched.
 */
static int resize_poll_event(struct lttng_poll_event *events,
		uint32_t new_size)
{
	struct epoll_event *ptr;

	LTTNG_ASSERT(events);

	ptr = (epoll_event *) realloc(events->events, new_size * sizeof(*ptr));
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
	events->events = (epoll_event *) zmalloc(size * sizeof(struct epoll_event));
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
int compat_epoll_wait(struct lttng_poll_event *events, int timeout,
		bool interruptible)
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
	} while (!interruptible && ret == -1 && errno == EINTR);
	if (ret < 0) {
		if (errno != EINTR) {
			PERROR("epoll_wait");
		}
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

#else /* HAVE_EPOLL */

#include <sys/resource.h>
#include <sys/time.h>

/*
 * Maximum number of fd we can monitor.
 *
 * For poll(2), the max fds must not exceed RLIMIT_NOFILE given by
 * getrlimit(2).
 */
static unsigned int poll_max_size;

/*
 * Resize the epoll events structure of the new size.
 *
 * Return 0 on success or else -1 with the current events pointer untouched.
 */
static int resize_poll_event(struct compat_poll_event_array *array,
		uint32_t new_size)
{
	struct pollfd *ptr;

	LTTNG_ASSERT(array);

	/* Refuse to resize the array more than the max size. */
	if (new_size > poll_max_size) {
		goto error;
	}

	ptr = (struct pollfd *) realloc(array->events, new_size * sizeof(*ptr));
	if (ptr == NULL) {
		PERROR("realloc epoll add");
		goto error;
	}
	if (new_size > array->alloc_size) {
		/* Zero newly allocated memory */
		memset(ptr + array->alloc_size, 0,
			(new_size - array->alloc_size) * sizeof(*ptr));
	}
	array->events = ptr;
	array->alloc_size = new_size;

	return 0;

error:
	return -1;
}

/*
 * Update events with the current events object.
 */
static int update_current_events(struct lttng_poll_event *events)
{
	int ret;
	struct compat_poll_event_array *current, *wait;

	LTTNG_ASSERT(events);

	current = &events->current;
	wait = &events->wait;

	wait->nb_fd = current->nb_fd;
	if (current->alloc_size != wait->alloc_size) {
		ret = resize_poll_event(wait, current->alloc_size);
		if (ret < 0) {
			goto error;
		}
	}
	memcpy(wait->events, current->events,
			current->nb_fd * sizeof(*current->events));

	/* Update is done. */
	events->need_update = 0;

	return 0;

error:
	return -1;
}

/*
 * Create pollfd data structure.
 */
int compat_poll_create(struct lttng_poll_event *events, int size)
{
	struct compat_poll_event_array *current, *wait;

	if (events == NULL || size <= 0) {
		ERR("Wrong arguments for poll create");
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

	/* Reset everything before begining the allocation. */
	memset(events, 0, sizeof(struct lttng_poll_event));

	current = &events->current;
	wait = &events->wait;

	/* This *must* be freed by using lttng_poll_free() */
	wait->events = (struct pollfd *) zmalloc(size * sizeof(struct pollfd));
	if (wait->events == NULL) {
		PERROR("zmalloc struct pollfd");
		goto error;
	}

	wait->alloc_size = wait->init_size = size;

	current->events = (struct pollfd *) zmalloc(size * sizeof(struct pollfd));
	if (current->events == NULL) {
		PERROR("zmalloc struct current pollfd");
		goto error;
	}

	current->alloc_size = current->init_size = size;

	return 0;

error:
	return -1;
}

/*
 * Add fd to pollfd data structure with requested events.
 */
int compat_poll_add(struct lttng_poll_event *events, int fd,
		uint32_t req_events)
{
	int new_size, ret, i;
	struct compat_poll_event_array *current;

	if (events == NULL || events->current.events == NULL || fd < 0) {
		ERR("Bad compat poll add arguments");
		goto error;
	}

	current = &events->current;

	/* Check if fd we are trying to add is already there. */
	for (i = 0; i < current->nb_fd; i++) {
		if (current->events[i].fd == fd) {
			errno = EEXIST;
			goto error;
		}
	}

	/* Resize array if needed. */
	new_size = 1U << utils_get_count_order_u32(current->nb_fd + 1);
	if (new_size != current->alloc_size && new_size >= current->init_size) {
		ret = resize_poll_event(current, new_size);
		if (ret < 0) {
			goto error;
		}
	}

	current->events[current->nb_fd].fd = fd;
	current->events[current->nb_fd].events = req_events;
	current->nb_fd++;
	events->need_update = 1;

	DBG("fd %d of %d added to pollfd", fd, current->nb_fd);

	return 0;

error:
	return -1;
}

/*
 * Modify an fd's events..
 */
int compat_poll_mod(struct lttng_poll_event *events, int fd,
		uint32_t req_events)
{
	int i;
	struct compat_poll_event_array *current;

	if (events == NULL || events->current.nb_fd == 0 ||
			events->current.events == NULL || fd < 0) {
		ERR("Bad compat poll mod arguments");
		goto error;
	}

	current = &events->current;

	for (i = 0; i < current->nb_fd; i++) {
		if (current->events[i].fd == fd) {
			current->events[i].events = req_events;
			events->need_update = 1;
			break;
		}
	}

	/*
	 * The epoll flavor doesn't flag modifying a non-included FD as an
	 * error.
	 */

	return 0;

error:
	return -1;
}

/*
 * Remove a fd from the pollfd structure.
 */
int compat_poll_del(struct lttng_poll_event *events, int fd)
{
	int i, count = 0, ret;
	uint32_t new_size;
	struct compat_poll_event_array *current;

	if (events == NULL || events->current.nb_fd == 0 ||
			events->current.events == NULL || fd < 0) {
		goto error;
	}

	/* Ease our life a bit. */
	current = &events->current;

	for (i = 0; i < current->nb_fd; i++) {
		/* Don't put back the fd we want to delete */
		if (current->events[i].fd != fd) {
			current->events[count].fd = current->events[i].fd;
			current->events[count].events = current->events[i].events;
			count++;
		}
	}

	/* The fd was not in our set, return no error as with epoll. */
	if (current->nb_fd == count) {
		goto end;
	}

	/* No fd duplicate should be ever added into array. */
	LTTNG_ASSERT(current->nb_fd - 1 == count);
	current->nb_fd = count;

	/* Resize array if needed. */
	new_size = 1U << utils_get_count_order_u32(current->nb_fd);
	if (new_size != current->alloc_size && new_size >= current->init_size
			&& current->nb_fd != 0) {
		ret = resize_poll_event(current, new_size);
		if (ret < 0) {
			goto error;
		}
	}

	events->need_update = 1;

end:
	return 0;

error:
	return -1;
}

/*
 * Wait on poll() with timeout. Blocking call.
 */
int compat_poll_wait(struct lttng_poll_event *events, int timeout,
		bool interruptible)
{
	int ret, active_fd_count;
	size_t pos = 0, consecutive_entries = 0, non_idle_pos;

	if (events == NULL || events->current.events == NULL) {
		ERR("poll wait arguments error");
		goto error;
	}

	if (events->current.nb_fd == 0) {
		/* Return an invalid error to be consistent with epoll. */
		errno = EINVAL;
		events->wait.nb_fd = 0;
		goto error;
	}

	if (events->need_update) {
		ret = update_current_events(events);
		if (ret < 0) {
			errno = ENOMEM;
			goto error;
		}
	}

	do {
		ret = poll(events->wait.events, events->wait.nb_fd, timeout);
	} while (!interruptible && ret == -1 && errno == EINTR);
	if (ret < 0) {
		if (errno != EINTR) {
			PERROR("poll wait");
		}
		goto error;
	}

	active_fd_count = ret;

	/*
	 * Move all active pollfd structs to the beginning of the
	 * array to emulate compat-epoll behaviour.
	 */
	if (active_fd_count == events->wait.nb_fd) {
		goto end;
	}

	while (consecutive_entries != active_fd_count) {
		struct pollfd *current = &events->wait.events[pos];
		struct pollfd idle_entry;

		if (current->revents != 0) {
			consecutive_entries++;
			pos++;
			continue;
		}

		non_idle_pos = pos;

		/* Look for next non-idle entry. */
		while (events->wait.events[++non_idle_pos].revents == 0);

		/* Swap idle and non-idle entries. */
		idle_entry = *current;
		*current = events->wait.events[non_idle_pos];
		events->wait.events[non_idle_pos] = idle_entry;

		consecutive_entries++;
		pos++;
	}
end:
	return ret;

error:
	return -1;
}

/*
 * Setup poll set maximum size.
 */
int compat_poll_set_max_size(void)
{
	int ret, retval = 0;
	struct rlimit lim;

	ret = getrlimit(RLIMIT_NOFILE, &lim);
	if (ret < 0) {
		PERROR("getrlimit poll RLIMIT_NOFILE");
		retval = -1;
		goto end;
	}

	poll_max_size = lim.rlim_cur;
end:
	if (poll_max_size == 0) {
		poll_max_size = DEFAULT_POLL_SIZE;
	}
	DBG("poll set max size set to %u", poll_max_size);
	return retval;
}

#endif /* !HAVE_EPOLL */
