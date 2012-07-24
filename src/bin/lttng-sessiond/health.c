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

#include "health.h"

static const struct timespec time_delta = {
	.tv_sec = DEFAULT_HEALTH_CHECK_DELTA_S,
	.tv_nsec = DEFAULT_HEALTH_CHECK_DELTA_NS,
};

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
		res->tv_nsec = time_a->tv_sec - time_b->tv_sec;
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
 * Check health of a specific health state counter.
 *
 * Return 0 if health is bad or else 1.
 */
int health_check_state(struct health_state *state)
{
	int retval = 1, ret;
	unsigned long current, last;
	struct timespec current_time;

	assert(state);

	last = state->last;
	current = uatomic_read(&state->current);

	ret = clock_gettime(CLOCK_MONOTONIC, &current_time);
	if (ret) {
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
		}
	}

end:
	DBG("Health state current %" PRIu64 ", last %" PRIu64 ", ret %d",
			current, last, ret);

	return retval;
}
