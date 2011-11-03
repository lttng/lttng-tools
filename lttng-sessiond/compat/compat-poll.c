/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <lttngerr.h>

#include "poll.h"

unsigned int poll_max_size;

/*
 * Create pollfd data structure.
 */
int compat_poll_create(struct lttng_poll_event *events, int size)
{
	if (events == NULL || size <= 0) {
		ERR("Wrong arguments for poll create");
		goto error;
	}

	/* Don't bust the limit here */
	if (size > poll_max_size) {
		size = poll_max_size;
	}

	/* This *must* be freed by using lttng_poll_free() */
	events->events = zmalloc(size * sizeof(struct pollfd));
	if (events->events == NULL) {
		perror("malloc struct pollfd");
		goto error;
	}

	events->events_size = size;
	events->nb_fd = 0;

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
	int new_size;
	struct pollfd *ptr;

	if (events == NULL || events->events == NULL || fd < 0) {
		ERR("Bad compat poll add arguments");
		goto error;
	}

	/* Reallocate pollfd structure by a factor of 2 if needed. */
	if (events->nb_fd >= events->events_size) {
		new_size = 2 * events->events_size;
		ptr = realloc(events->events, new_size * sizeof(struct pollfd));
		if (ptr == NULL) {
			perror("realloc poll add");
			goto error;
		}
		events->events = ptr;
		events->events_size = new_size;
	}

	events->events[events->nb_fd].fd = fd;
	events->events[events->nb_fd].events = req_events;
	events->nb_fd++;

	DBG("fd %d of %d added to pollfd", fd, events->nb_fd);

	return 0;

error:
	return -1;
}

/*
 * Remove a fd from the pollfd structure.
 */
int compat_poll_del(struct lttng_poll_event *events, int fd)
{
	int new_size, i, count = 0;
	struct pollfd *old = NULL, *new = NULL;

	if (events == NULL || events->events == NULL || fd < 0) {
		ERR("Wrong arguments for poll del");
		goto error;
	}

	old = events->events;
	new_size = events->events_size - 1;

	/* Safety check on size */
	if (new_size > poll_max_size) {
		new_size = poll_max_size;
	}

	new = zmalloc(new_size * sizeof(struct pollfd));
	if (new == NULL) {
		perror("malloc poll del");
		goto error;
	}

	for (i = 0; i < events->events_size; i++) {
		/* Don't put back the fd we want to delete */
		if (old[i].fd != fd) {
			new[count].fd = old[i].fd;
			new[count].events = old[i].events;
			count++;
		}
	}

	events->events_size = new_size;
	events->events = new;
	events->nb_fd--;

	free(old);

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

	if (events == NULL || events->events == NULL ||
			events->events_size < events->nb_fd) {
		ERR("poll wait arguments error");
		goto error;
	}

	ret = poll(events->events, events->nb_fd, timeout);
	if (ret < 0) {
		/* At this point, every error is fatal */
		perror("poll wait");
		goto error;
	}

	return ret;

error:
	return -1;
}

/*
 * Setup poll set maximum size.
 */
void compat_poll_set_max_size(void)
{
	int ret;
	struct rlimit lim;

	/* Default value */
	poll_max_size = LTTNG_POLL_DEFAULT_SIZE;

	ret = getrlimit(RLIMIT_NOFILE, &lim);
	if (ret < 0) {
		perror("getrlimit poll RLIMIT_NOFILE");
		return;
	}

	poll_max_size = lim.rlim_cur;
	if (poll_max_size <= 0) {
		/* Extra precaution */
		poll_max_size = LTTNG_POLL_DEFAULT_SIZE;
	}

	DBG("poll set max size set to %u", poll_max_size);
}
