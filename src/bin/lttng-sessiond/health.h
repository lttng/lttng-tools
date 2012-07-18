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

#ifndef _HEALTH_H
#define _HEALTH_H

#include <stdint.h>
#include <urcu/uatomic.h>

/*
 * These are the value added to the current state depending of the position in
 * the thread where is either waiting on a poll() or running in the code.
 */
#define HEALTH_POLL_VALUE 1
#define HEALTH_CODE_VALUE 2

#define HEALTH_IS_IN_POLL(x) (x % HEALTH_CODE_VALUE)
#define HEALTH_IS_IN_CODE(x) (x % HEALTH_POLL_VALUE)

struct health_state {
	uint64_t last;
	uint64_t current;
};

/* Health state counters for the client command thread */
extern struct health_state health_thread_cmd;

/* Health state counters for the application registration thread */
extern struct health_state health_thread_app_reg;

/* Health state counters for the kernel thread */
extern struct health_state health_thread_kernel;

/*
 * Update current counter by 1 to indicate that the thread is in a blocking
 * state cause by a poll().
 */
static inline void health_poll_update(struct health_state *state)
{
	assert(state);

	uatomic_add(&state->current, HEALTH_POLL_VALUE);
}

/*
 * Update current counter by 2 which indicates that we are currently running in
 * a thread and NOT blocked at a poll().
 */
static inline void health_code_update(struct health_state *state)
{
	assert(state);

	uatomic_add(&state->current, HEALTH_CODE_VALUE);
}

/*
 * Reset health state. A value of zero indicate a bad health state.
 */
static inline void health_reset(struct health_state *state)
{
	assert(state);

	uatomic_set(&state->current, 0);
	uatomic_set(&state->last, 0);
}

/*
 * Init health state.
 */
static inline void health_init(struct health_state *state)
{
	assert(state);

	uatomic_set(&state->last, 0);
	uatomic_set(&state->current, HEALTH_CODE_VALUE);
}

int health_check_state(struct health_state *state);

#endif /* _HEALTH_H */
