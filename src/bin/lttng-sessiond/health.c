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

#include <common/error.h>

#include "health.h"

/*
 * Check health of a specific health state counter.
 *
 * Return 0 if health is bad or else 1.
 */
int health_check_state(struct health_state *state)
{
	unsigned long current, last;
	int ret = 1;

	assert(state);

	last = state->last;
	current = uatomic_read(&state->current);

	/*
	 * Here are the conditions for a bad health. Either flag HEALTH_ERROR is
	 * set, or the progress counter is the same as the last one and we are NOT
	 * waiting for a poll() call.
	 */
	if ((uatomic_read(&state->flags) & HEALTH_ERROR) ||
			(current == last && !HEALTH_IS_IN_POLL(current))) {
		/* error */
		ret = 0;
	}

	DBG("Health state current %" PRIu64 ", last %" PRIu64 ", ret %d",
			current, last, ret);

	/*
	 * Update last counter. This value is and MUST be access only in this
	 * function.
	 */
	state->last = current;

	return ret;
}
