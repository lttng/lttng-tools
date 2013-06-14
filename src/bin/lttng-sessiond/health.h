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

#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <urcu/tls-compat.h>
#include <urcu/uatomic.h>
#include <urcu/list.h>

/*
 * These are the value added to the current state depending of the position in
 * the thread where is either waiting on a poll() or running in the code.
 */
#define HEALTH_POLL_VALUE 	(1UL << 0)
#define HEALTH_CODE_VALUE	(1UL << 1)

#define HEALTH_IS_IN_POLL(x)	((x) & HEALTH_POLL_VALUE)

enum health_flags {
	HEALTH_ERROR = (1U << 0),
};

enum health_type {
	HEALTH_TYPE_CMD			= 0,
	HEALTH_TYPE_APP_MANAGE	= 1,
	HEALTH_TYPE_APP_REG		= 2,
	HEALTH_TYPE_KERNEL		= 3,
	HEALTH_TYPE_CONSUMER	= 4,
	HEALTH_TYPE_HT_CLEANUP		= 5,
	HEALTH_TYPE_APP_MANAGE_NOTIFY	= 6,

	HEALTH_NUM_TYPE,
};

struct health_tls_state_list {
	struct cds_list_head head;
};

struct health_state {
	/*
	 * last counter and last_time are only read and updated by the health_check
	 * thread (single updater).
	 */
	unsigned long last;
	struct timespec last_time;

	/*
	 * current and flags are updated by multiple threads concurrently.
	 */
	unsigned long current;		/* progress counter, updated atomically */
	enum health_flags flags;	/* other flags, updated atomically */
	enum health_type type;		/* Indicates the nature of the thread. */
	/* Node of the global TLS state list. */
	struct cds_list_head node;
};

/* Declare TLS health state. */
extern DECLARE_URCU_TLS(struct health_state, health_state);

/*
 * Update current counter by 1 to indicate that the thread entered or left a
 * blocking state caused by a poll(). If the counter's value is not an even
 * number (meaning a code execution flow), an assert() is raised.
 */
static inline void health_poll_entry(void)
{
	/* Code MUST be in code execution state which is an even number. */
	assert(!(uatomic_read(&URCU_TLS(health_state).current)
				& HEALTH_POLL_VALUE));

	uatomic_add(&URCU_TLS(health_state).current, HEALTH_POLL_VALUE);
}

/*
 * Update current counter by 1 indicating the exit of a poll or blocking call.
 * If the counter's value is not an odd number (a poll execution), an assert()
 * is raised.
 */
static inline void health_poll_exit(void)
{
	/* Code MUST be in poll execution state which is an odd number. */
	assert(uatomic_read(&URCU_TLS(health_state).current)
				& HEALTH_POLL_VALUE);

	uatomic_add(&URCU_TLS(health_state).current, HEALTH_POLL_VALUE);
}

/*
 * Update current counter by 2 indicates progress in execution of a
 * thread.
 */
static inline void health_code_update(void)
{
	uatomic_add(&URCU_TLS(health_state).current, HEALTH_CODE_VALUE);
}

/*
 * Set health "error" flag.
 */
static inline void health_error(void)
{
	uatomic_or(&URCU_TLS(health_state).flags, HEALTH_ERROR);
}

int health_check_state(enum health_type type);
void health_register(enum health_type type);
void health_unregister(void);

#endif /* _HEALTH_H */
