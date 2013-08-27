/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <common/defaults.h>
#include <common/error.h>
#include <common/macros.h>
#include <common/sessiond-comm/inet.h>

#include "health.h"

static struct timespec time_delta = {
	.tv_sec = DEFAULT_HEALTH_CHECK_DELTA_S,
	.tv_nsec = DEFAULT_HEALTH_CHECK_DELTA_NS,
};

/* Define TLS health state. */
DEFINE_URCU_TLS(struct health_state, health_state);

/*
 * It ensures that TLS memory used for the node and its container structure
 * don't get reclaimed after the TLS owner thread exits until we have finished
 * using it.
 */
static pthread_mutex_t health_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct health_tls_state_list health_state_list = {
	.head = CDS_LIST_HEAD_INIT(health_state_list.head),
};

/*
 * This keeps track of the error state for unregistered thread. A thread
 * reporting a health error, normally unregisters and quits. This makes the TLS
 * health state not available to the health_check_state() call so on unregister
 * we update this global error array so we can keep track of which thread was
 * on error if the TLS health state has been removed.
 */
static enum health_flags global_error_state[HEALTH_NUM_TYPE];

/*
 * Lock health state global list mutex.
 */
static void state_lock(void)
{
	pthread_mutex_lock(&health_mutex);
}

/*
 * Unlock health state global list mutex.
 */
static void state_unlock(void)
{
	pthread_mutex_unlock(&health_mutex);
}

/*
 * Set time difference in res from time_a and time_b.
 */
static void time_diff(const struct timespec *time_a,
		const struct timespec *time_b, struct timespec *res)
{
	if (time_a->tv_nsec - time_b->tv_nsec < 0) {
		res->tv_sec = time_a->tv_sec - time_b->tv_sec - 1;
		res->tv_nsec = 1000000000L + time_a->tv_sec - time_b->tv_sec;
	} else {
		res->tv_sec = time_a->tv_sec - time_b->tv_sec;
		res->tv_nsec = time_a->tv_nsec - time_b->tv_nsec;
	}
}

/*
 * Return true if time_a - time_b > diff, else false.
 */
static int time_diff_gt(const struct timespec *time_a,
		const struct timespec *time_b, const struct timespec *diff)
{
	struct timespec res;

	time_diff(time_a, time_b, &res);
	time_diff(&res, diff, &res);

	if (res.tv_sec > 0) {
		return 1;
	} else if (res.tv_sec == 0 && res.tv_nsec > 0) {
		return 1;
	}

	return 0;
}

/*
 * Validate health state. Checks for the error flag or health conditions.
 *
 * Return 0 if health is bad or else 1.
 */
static int validate_state(struct health_state *state)
{
	int retval = 1, ret;
	unsigned long current, last;
	struct timespec current_time;

	assert(state);

	last = state->last;
	current = uatomic_read(&state->current);

	ret = clock_gettime(CLOCK_MONOTONIC, &current_time);
	if (ret < 0) {
		PERROR("Error reading time\n");
		/* error */
		retval = 0;
		goto end;
	}

	/*
	 * Thread is in bad health if flag HEALTH_ERROR is set. It is also in bad
	 * health if, after the delta delay has passed, its the progress counter
	 * has not moved and it has NOT been waiting for a poll() call.
	 */
	if (uatomic_read(&state->flags) & HEALTH_ERROR) {
		retval = 0;
		goto end;
	}

	/*
	 * Initial condition need to update the last counter and sample time, but
	 * should not check health in this initial case, because we don't know how
	 * much time has passed.
	 */
	if (state->last_time.tv_sec == 0 && state->last_time.tv_nsec == 0) {
		/* update last counter and last sample time */
		state->last = current;
		memcpy(&state->last_time, &current_time, sizeof(current_time));
	} else {
		if (time_diff_gt(&current_time, &state->last_time, &time_delta)) {
			if (current == last && !HEALTH_IS_IN_POLL(current)) {
				/* error */
				retval = 0;
			}
			/* update last counter and last sample time */
			state->last = current;
			memcpy(&state->last_time, &current_time, sizeof(current_time));

			/* On error, stop right now and notify caller. */
			if (retval == 0) {
				goto end;
			}
		}
	}

end:
	DBG("Health state current %lu, last %lu, ret %d",
			current, last, ret);
	return retval;
}

/*
 * Check health of a specific health type. Note that if a thread has not yet
 * initialize its health subsystem or has quit, it's considered in a good
 * state.
 *
 * Return 0 if health is bad or else 1.
 */
int health_check_state(enum health_type type)
{
	int retval = 1;
	struct health_state *state;

	assert(type < HEALTH_NUM_TYPE);

	state_lock();

	cds_list_for_each_entry(state, &health_state_list.head, node) {
		int ret;

		if (state->type != type) {
			continue;
		}

		ret = validate_state(state);
		if (!ret) {
			retval = 0;
			goto end;
		}
	}

	/* Check the global state since some state might not be visible anymore. */
	if (global_error_state[type] & HEALTH_ERROR) {
		retval = 0;
	}

end:
	state_unlock();

	DBG("Health check for type %d is %s", (int) type,
			(retval == 0) ? "BAD" : "GOOD");
	return retval;
}

/*
 * Init health state.
 */
void health_register(enum health_type type)
{
	assert(type < HEALTH_NUM_TYPE);

	/* Init TLS state. */
	uatomic_set(&URCU_TLS(health_state).last, 0);
	uatomic_set(&URCU_TLS(health_state).last_time.tv_sec, 0);
	uatomic_set(&URCU_TLS(health_state).last_time.tv_nsec, 0);
	uatomic_set(&URCU_TLS(health_state).current, 0);
	uatomic_set(&URCU_TLS(health_state).flags, 0);
	uatomic_set(&URCU_TLS(health_state).type, type);

	/* Add it to the global TLS state list. */
	state_lock();
	cds_list_add(&URCU_TLS(health_state).node, &health_state_list.head);
	state_unlock();
}

/*
 * Remove node from global list.
 */
void health_unregister(void)
{
	state_lock();
	/*
	 * On error, set the global_error_state since we are about to remove
	 * the node from the global list.
	 */
	if (uatomic_read(&URCU_TLS(health_state).flags) & HEALTH_ERROR) {
		uatomic_set(&global_error_state[URCU_TLS(health_state).type],
				HEALTH_ERROR);
	}
	cds_list_del(&URCU_TLS(health_state).node);
	state_unlock();
}

/*
 * Initiliazie health check subsytem. This should be called before any health
 * register occurs.
 */
void health_init(void)
{
	/*
	 * Get the maximum value between the default delta value and the TCP
	 * timeout with a safety net of the default health check delta.
	 */
	time_delta.tv_sec = max_t(unsigned long,
			lttcomm_inet_tcp_timeout + DEFAULT_HEALTH_CHECK_DELTA_S,
			time_delta.tv_sec);
	DBG("Health check time delta in seconds set to %lu", time_delta.tv_sec);
}
