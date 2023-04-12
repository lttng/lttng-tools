#ifndef HEALTH_INTERNAL_H
#define HEALTH_INTERNAL_H

/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/compat/time.hpp>
#include <common/macros.hpp>

#include <lttng/health.h>

#include <pthread.h>
#include <urcu/list.h>
#include <urcu/tls-compat.h>
#include <urcu/uatomic.h>

/*
 * These are the value added to the current state depending of the position in
 * the thread where is either waiting on a poll() or running in the code.
 */
#define HEALTH_POLL_VALUE (1UL << 0)
#define HEALTH_CODE_VALUE (1UL << 1)

#define HEALTH_IS_IN_POLL(x) ((x) &HEALTH_POLL_VALUE)

struct health_app;

enum health_flags {
	HEALTH_ERROR = (1U << 0),
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
	unsigned long current; /* progress counter, updated atomically */
	enum health_flags flags; /* other flags, updated atomically */
	int type; /* Indicates the nature of the thread. */
	/* Node of the global TLS state list. */
	struct cds_list_head node;
};

enum health_cmd {
	HEALTH_CMD_CHECK = 0,
};

struct health_comm_msg {
	uint32_t cmd; /* enum health_cmd */
} LTTNG_PACKED;

struct health_comm_reply {
	uint64_t ret_code; /* bitmask of threads in bad health */
} LTTNG_PACKED;

/* Declare TLS health state. */
extern DECLARE_URCU_TLS(struct health_state, health_state);

/*
 * Update current counter by 1 to indicate that the thread entered or left a
 * blocking state caused by a poll(). If the counter's value is not an even
 * number (meaning a code execution flow), an LTTNG_ASSERT() is raised.
 */
static inline void health_poll_entry()
{
	/* Code MUST be in code execution state which is an even number. */
	LTTNG_ASSERT(!(uatomic_read(&URCU_TLS(health_state).current) & HEALTH_POLL_VALUE));

	uatomic_add(&URCU_TLS(health_state).current, HEALTH_POLL_VALUE);
}

/*
 * Update current counter by 1 indicating the exit of a poll or blocking call.
 * If the counter's value is not an odd number (a poll execution), an LTTNG_ASSERT()
 * is raised.
 */
static inline void health_poll_exit()
{
	/* Code MUST be in poll execution state which is an odd number. */
	LTTNG_ASSERT(uatomic_read(&URCU_TLS(health_state).current) & HEALTH_POLL_VALUE);

	uatomic_add(&URCU_TLS(health_state).current, HEALTH_POLL_VALUE);
}

/*
 * Update current counter by 2 indicates progress in execution of a
 * thread.
 */
static inline void health_code_update()
{
	uatomic_add(&URCU_TLS(health_state).current, HEALTH_CODE_VALUE);
}

/*
 * Set health "error" flag.
 */
static inline void health_error()
{
	uatomic_or(&URCU_TLS(health_state).flags, HEALTH_ERROR);
}

struct health_app *health_app_create(int nr_types);
void health_app_destroy(struct health_app *ha);
int health_check_state(struct health_app *ha, int type);
void health_register(struct health_app *ha, int type);
void health_unregister(struct health_app *ha);

#endif /* HEALTH_INTERNAL_H */
