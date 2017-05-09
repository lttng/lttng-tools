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
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <stdbool.h>

#include <common/defaults.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/utils.h>

#include "poll.h"

unsigned int poll_max_size;

/*
 * Resize the epoll events structure of the new size.
 *
 * Return 0 on success or else -1 with the current events pointer untouched.
 */
static int resize_poll_event(struct compat_poll_event_array *array,
		uint32_t new_size)
{
	struct pollfd *ptr;

	assert(array);

	/* Refuse to resize the array more than the max size. */
	if (new_size > poll_max_size) {
		goto error;
	}

	ptr = realloc(array->events, new_size * sizeof(*ptr));
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

	assert(events);

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
	wait->events = zmalloc(size * sizeof(struct pollfd));
	if (wait->events == NULL) {
		PERROR("zmalloc struct pollfd");
		goto error;
	}

	wait->alloc_size = wait->init_size = size;

	current->events = zmalloc(size * sizeof(struct pollfd));
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
	bool fd_found = false;
	struct compat_poll_event_array *current;

	if (events == NULL || events->current.events == NULL || fd < 0) {
		ERR("Bad compat poll mod arguments");
		goto error;
	}

	current = &events->current;

	for (i = 0; i < current->nb_fd; i++) {
		if (current->events[i].fd == fd) {
			fd_found = true;
			current->events[i].events = req_events;
			events->need_update = 1;
			break;
		}
	}

	if (!fd_found) {
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Remove a fd from the pollfd structure.
 */
int compat_poll_del(struct lttng_poll_event *events, int fd)
{
	int new_size, i, count = 0, ret;
	struct compat_poll_event_array *current;

	if (events == NULL || events->current.events == NULL || fd < 0) {
		ERR("Wrong arguments for poll del");
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
	/* No fd duplicate should be ever added into array. */
	assert(current->nb_fd - 1 == count);
	current->nb_fd = count;

	/* Resize array if needed. */
	new_size = 1U << utils_get_count_order_u32(current->nb_fd);
	if (new_size != current->alloc_size && new_size >= current->init_size) {
		ret = resize_poll_event(current, new_size);
		if (ret < 0) {
			goto error;
		}
	}

	events->need_update = 1;

	return 0;

error:
	return -1;
}

/*
 * Wait on poll() with timeout. Blocking call.
 */
int compat_poll_wait(struct lttng_poll_event *events, int timeout)
{
	int ret;

	if (events == NULL || events->current.events == NULL) {
		ERR("poll wait arguments error");
		goto error;
	}
	assert(events->current.nb_fd >= 0);

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
	} while (ret == -1 && errno == EINTR);
	if (ret < 0) {
		/* At this point, every error is fatal */
		PERROR("poll wait");
		goto error;
	}

	/*
	 * poll() should always iterate on all FDs since we handle the pollset in
	 * user space and after poll returns, we have to try every fd for a match.
	 */
	return events->wait.nb_fd;

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
