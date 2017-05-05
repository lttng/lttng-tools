/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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

#ifndef _LTT_POLL_H
#define _LTT_POLL_H

#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <common/common.h>

/*
 * Maximum number of fd we can monitor.
 *
 * For epoll(7), /proc/sys/fs/epoll/max_user_watches (since Linux 2.6.28) will
 * be used for the maximum size of the poll set. If this interface is not
 * available, according to the manpage, the max_user_watches value is 1/25 (4%)
 * of the available low memory divided by the registration cost in bytes which
 * is 90 bytes on a 32-bit kernel and 160 bytes on a 64-bit kernel.
 *
 * For poll(2), the max fds must not exceed RLIMIT_NOFILE given by
 * getrlimit(2).
 */
extern unsigned int poll_max_size;

/*
 * Used by lttng_poll_clean to free the events structure in a lttng_poll_event.
 */
static inline void __lttng_poll_free(void *events)
{
	free(events);
}

/*
 * epoll(7) implementation.
 */
#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#include <stdio.h>
#include <features.h>
#include <common/compat/fcntl.h>

/* See man epoll(7) for this define path */
#define COMPAT_EPOLL_PROC_PATH "/proc/sys/fs/epoll/max_user_watches"

enum {
	/* Polling variables compatibility for epoll */
	LPOLLIN = EPOLLIN,
	LPOLLPRI = EPOLLPRI,
	LPOLLOUT = EPOLLOUT,
	LPOLLRDNORM = EPOLLRDNORM,
	LPOLLRDBAND = EPOLLRDBAND,
	LPOLLWRNORM = EPOLLWRNORM,
	LPOLLWRBAND = EPOLLWRBAND,
	LPOLLMSG = EPOLLMSG,
	LPOLLERR = EPOLLERR,
	LPOLLHUP = EPOLLHUP,
	LPOLLNVAL = EPOLLHUP,
	LPOLLRDHUP = EPOLLRDHUP,
	/* Close on exec feature of epoll */
#if defined(HAVE_EPOLL_CREATE1) && defined(EPOLL_CLOEXEC)
	LTTNG_CLOEXEC = EPOLL_CLOEXEC,
#else
	/*
	 * EPOLL_CLOEXEC was added in glibc 2.8 (usually used in conjunction with
	 * epoll_create1(..)), but since neither EPOLL_CLOEXEC exists nor
	 * epoll_create1(..), we set it to FD_CLOEXEC so that we can pass it
	 * directly to fcntl(..) instead.
	 */
	LTTNG_CLOEXEC = FD_CLOEXEC,
#endif
};

struct compat_epoll_event {
	int epfd;
	uint32_t nb_fd;       /* Current number of fd in events */
	uint32_t alloc_size; /* Size of events array */
	uint32_t init_size;	/* Initial size of events array */
	struct epoll_event *events;
};
#define lttng_poll_event compat_epoll_event

static inline int __lttng_epoll_get_prev_fd(struct lttng_poll_event *events,
		int index, uint32_t nb_fd)
{
	assert(events);
	assert(index != nb_fd);

	if (index == 0 || nb_fd == 0) {
		return -1;
	} else {
		return events->events[index - 1].data.fd;
	}
}

/*
 * For the following calls, consider 'e' to be a lttng_poll_event pointer and i
 * being the index of the events array.
 */
#define LTTNG_POLL_GETFD(e, i) LTTNG_REF(e)->events[i].data.fd
#define LTTNG_POLL_GETEV(e, i) LTTNG_REF(e)->events[i].events
#define LTTNG_POLL_GETNB(e) LTTNG_REF(e)->nb_fd
#define LTTNG_POLL_GETSZ(e) LTTNG_REF(e)->events_size
#define LTTNG_POLL_GET_PREV_FD(e, i, nb_fd) \
	__lttng_epoll_get_prev_fd(LTTNG_REF(e), i, nb_fd)

/*
 * Create the epoll set. No memory allocation is done here.
 */
extern int compat_epoll_create(struct lttng_poll_event *events,
		int size, int flags);
#define lttng_poll_create(events, size, flags) \
	compat_epoll_create(events, size, flags)

#if defined(HAVE_EPOLL_CREATE1) && defined(EPOLL_CLOEXEC)
static inline int compat_glibc_epoll_create(int size __attribute__((unused)),
		int flags)
{
	return epoll_create1(flags);
}
#else
static inline int compat_glibc_epoll_create(int size, int flags)
{
	/*
	 * epoll_create1 was added in glibc 2.9, but unfortunatly reverting to
	 * epoll_create(..) also means that we lose the possibility to
	 * directly set the EPOLL_CLOEXEC, so try and do it anyway but through
	 * fcntl(..).
	 */
	int efd = epoll_create(size);
	assert(fcntl(efd, F_SETFD, flags) != -1);
	return efd;
}
#endif

/*
 * Wait on epoll set with the number of fd registered to the lttng_poll_event
 * data structure (events).
 */
extern int compat_epoll_wait(struct lttng_poll_event *events, int timeout);
#define lttng_poll_wait(events, timeout) \
	compat_epoll_wait(events, timeout)

/*
 * Add a fd to the epoll set and resize the epoll_event structure if needed.
 */
extern int compat_epoll_add(struct lttng_poll_event *events,
		int fd, uint32_t req_events);
#define lttng_poll_add(events, fd, req_events) \
	compat_epoll_add(events, fd, req_events)

/*
 * Remove a fd from the epoll set.
 */
extern int compat_epoll_del(struct lttng_poll_event *events, int fd);
#define lttng_poll_del(events, fd) \
	compat_epoll_del(events, fd)

/*
 * Modify an fd's events in the epoll set.
 */
extern int compat_epoll_mod(struct lttng_poll_event *events,
		int fd, uint32_t req_events);
#define lttng_poll_mod(events, fd, req_events) \
	compat_epoll_add(events, fd, req_events)

/*
 * Set up the poll set limits variable poll_max_size
 */
extern int compat_epoll_set_max_size(void);
#define lttng_poll_set_max_size() \
	compat_epoll_set_max_size()

/*
 * This function memset with zero the structure since it can be reused at each
 * round of a main loop. Being in a loop and using a non static number of fds,
 * this function must be called to insure coherent events with associted fds.
 */
static inline void lttng_poll_reset(struct lttng_poll_event *events)
{
	if (events && events->events) {
		memset(events->events, 0,
				events->nb_fd * sizeof(struct epoll_event));
	}
}

/*
 * Initialize an already allocated poll event data structure. For epoll(), the
 * epfd is set to -1 to indicate that it's not usable.
 */
static inline void lttng_poll_init(struct lttng_poll_event *events)
{
	memset(events, 0, sizeof(struct lttng_poll_event));
	/* Set fd to -1 so if clean before created, we don't close 0. */
	events->epfd = -1;
}

/*
 * Clean the events structure of a lttng_poll_event. It's the caller
 * responsability to free the lttng_poll_event memory.
 */
static inline void lttng_poll_clean(struct lttng_poll_event *events)
{
	int ret;

	if (!events) {
		return;
	}

	if (events->epfd >= 0) {
		ret = close(events->epfd);
		if (ret) {
			PERROR("close");
		}
	}

	__lttng_poll_free((void *) events->events);
}

#else	/* HAVE_EPOLL */
/*
 * Fallback on poll(2) API
 */

/* Needed for some poll event values */
#ifndef __USE_XOPEN
#define __USE_XOPEN
#endif

/* Needed for some poll event values */
#ifndef __USE_GNU
#define __USE_GNU
#endif

#include <poll.h>
#include <stdint.h>

enum {
	/* Polling variables compatibility for poll */
	LPOLLIN = POLLIN,
	LPOLLPRI = POLLPRI,
	LPOLLOUT = POLLOUT,
	LPOLLRDNORM = POLLRDNORM,
	LPOLLRDBAND = POLLRDBAND,
	LPOLLWRNORM = POLLWRNORM,
	LPOLLWRBAND = POLLWRBAND,
#if __linux__
	LPOLLMSG = POLLMSG,
	LPOLLRDHUP = POLLRDHUP,
#elif (defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__) || defined(__APPLE__))
	LPOLLMSG = 0,
	LPOLLRDHUP = 0,
#else
#error "Please add support for your OS."
#endif /* __linux__ */
	LPOLLERR = POLLERR,
	LPOLLHUP = POLLHUP | POLLNVAL,
	/* Close on exec feature does not exist for poll(2) */
	LTTNG_CLOEXEC = 0xdead,
};

struct compat_poll_event_array {
	uint32_t nb_fd;       /* Current number of fd in events */
	uint32_t alloc_size; /* Size of events array */
	/* Initial size of the pollset. We never shrink below that. */
	uint32_t init_size;
	struct pollfd *events;
};

struct compat_poll_event {
	/*
	 * Modified by the wait action. Updated using current fields if the
	 * need_update flag is set.
	 */
	struct compat_poll_event_array wait;
	/*
	 * This is modified by add/del actions being the _current_ flow of
	 * execution before a poll wait is done.
	 */
	struct compat_poll_event_array current;

	/* Indicate if wait.events need to be updated from current. */
	int need_update:1;
};
#define lttng_poll_event compat_poll_event

static inline int __lttng_poll_get_prev_fd(struct lttng_poll_event *events,
		int index, uint32_t nb_fd)
{
	assert(events);
	assert(index != nb_fd);

	if (index == 0 || nb_fd == 0) {
		return -1;
	} else {
		return events->current.events[index - 1].fd;
	}
}

/*
 * For the following calls, consider 'e' to be a lttng_poll_event pointer and i
 * being the index of the events array.
 */
#define LTTNG_POLL_GETFD(e, i) LTTNG_REF(e)->wait.events[i].fd
#define LTTNG_POLL_GETEV(e, i) LTTNG_REF(e)->wait.events[i].revents
#define LTTNG_POLL_GETNB(e) LTTNG_REF(e)->wait.nb_fd
#define LTTNG_POLL_GETSZ(e) LTTNG_REF(e)->wait.events_size
#define LTTNG_POLL_GET_PREV_FD(e, i, nb_fd) \
	__lttng_poll_get_prev_fd(LTTNG_REF(e), i, nb_fd)

/*
 * Create a pollfd structure of size 'size'.
 */
extern int compat_poll_create(struct lttng_poll_event *events, int size);
#define lttng_poll_create(events, size, flags) \
	compat_poll_create(events, size)

/*
 * Wait on poll(2) event with nb_fd registered to the lttng_poll_event data
 * structure.
 */
extern int compat_poll_wait(struct lttng_poll_event *events, int timeout);
#define lttng_poll_wait(events, timeout) \
	compat_poll_wait(events, timeout)

/*
 * Add the fd to the pollfd structure. Resize if needed.
 */
extern int compat_poll_add(struct lttng_poll_event *events,
		int fd, uint32_t req_events);
#define lttng_poll_add(events, fd, req_events) \
	compat_poll_add(events, fd, req_events)

/*
 * Remove the fd from the pollfd. Memory allocation is done to recreate a new
 * pollfd, data is copied from the old pollfd to the new and, finally, the old
 * one is freed().
 */
extern int compat_poll_del(struct lttng_poll_event *events, int fd);
#define lttng_poll_del(events, fd) \
	compat_poll_del(events, fd)

/*
 * Modify an fd's events in the epoll set.
 */
extern int compat_poll_mod(struct lttng_poll_event *events,
		int fd, uint32_t req_events);
#define lttng_poll_mod(events, fd, req_events) \
	compat_poll_add(events, fd, req_events)

/*
 * Set up the poll set limits variable poll_max_size
 */
extern int compat_poll_set_max_size(void);
#define lttng_poll_set_max_size() \
	compat_poll_set_max_size()

/*
 * No need to reset a pollfd structure for poll(2)
 */
static inline void lttng_poll_reset(struct lttng_poll_event *events)
{}

/*
 * Initialize an already allocated poll event data structure.
 */
static inline void lttng_poll_init(struct lttng_poll_event *events)
{
	memset(events, 0, sizeof(struct lttng_poll_event));
}

/*
 * Clean the events structure of a lttng_poll_event. It's the caller
 * responsability to free the lttng_poll_event memory.
 */
static inline void lttng_poll_clean(struct lttng_poll_event *events)
{
	if (events) {
		__lttng_poll_free((void *) events->wait.events);
		__lttng_poll_free((void *) events->current.events);
	}
}

#endif /* HAVE_EPOLL */

#endif /* _LTT_POLL_H */
