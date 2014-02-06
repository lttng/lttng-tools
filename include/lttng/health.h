#ifndef LTTNG_HEALTH_H
#define LTTNG_HEALTH_H

/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_health;
struct lttng_health_thread;

enum lttng_health_consumerd {
	LTTNG_HEALTH_CONSUMERD_UST_32,
	LTTNG_HEALTH_CONSUMERD_UST_64,
	LTTNG_HEALTH_CONSUMERD_KERNEL,

	NR_LTTNG_HEALTH_CONSUMERD,
};

/**
 * lttng_health_create_sessiond - Create sessiond health object
 *
 * Return a newly allocated health object, or NULL on error.
 */
struct lttng_health *lttng_health_create_sessiond(void);

/**
 * lttng_health_create_consumerd - Create consumerd health object
 * @consumerd: consumer daemon identifier
 *
 * Return a newly allocated health object, or NULL on error.
 */
struct lttng_health *
	lttng_health_create_consumerd(enum lttng_health_consumerd consumerd);

/**
 * lttng_health_create_relayd - Create relayd health object
 * @path: path to relay daemon health socket.
 *
 * "path" needs to refer to a local unix socket file matching the file
 * used by the relay daemon to query.
 *
 * Return a newly allocated health object, or NULL on error.
 */
struct lttng_health *lttng_health_create_relayd(const char *path);

/**
 * lttng_health_destroy - Destroy health object
 * @health: health object to destroy
 */
void lttng_health_destroy(struct lttng_health *health);

/**
 * lttng_health_query - Query component health
 * @health: health state (input/output).
 *
 * Return 0 on success, negative value on error. This return value only
 * reports if the query has been successfully performed, *NOT* the
 * actual state. lttng_health_state() should be used for the latter.
 */
int lttng_health_query(struct lttng_health *health);

/**
 * lttng_health_state - Inspect the state of a health structure
 * @health: health state (input).
 *
 * "path" needs to refer to a local unix socket file matching the file
 * used by the relay daemon to query.
 *
 * Return 0 on success, negative value if the component has at least one
 * thread in error. It also returns a negative return value if
 * lttng_health_query() has not yet successfully completed on @health.
 */
int lttng_health_state(const struct lttng_health *health);

/**
 * lttng_health_get_nr_threads - Get number of threads in health component
 * @health: health state (input)
 *
 * Return the number of threads (>= 0) on success, else negative value
 * on error.
 */
int lttng_health_get_nr_threads(const struct lttng_health *health);

/**
 * lttng_health_get_thread - Get thread health
 * @health: health state (input)
 * @nth_thread: nth thread to lookup
 *
 * Return a pointer to the health thread, else NULL on error. This
 * pointer should not be freed by the caller, and can be used until
 * lttng_health_destroy() is called on @health.
 */
const struct lttng_health_thread *
	lttng_health_get_thread(const struct lttng_health *health,
		unsigned int nth_thread);

/**
 * lttng_health_thread_state - Get thread health state
 * @thread: thread health
 *
 * Return 0 if thread is OK, else negative error value.
 */
int lttng_health_thread_state(const struct lttng_health_thread *thread);

/**
 * lttng_health_thread_name - Get thread name
 * @thread: thread health
 *
 * Return thread name, NULL on error.
 */
const char *lttng_health_thread_name(const struct lttng_health_thread *thread);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_HEALTH_H */
