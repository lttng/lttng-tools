/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SESSIOND_TIMER_H
#define SESSIOND_TIMER_H

#include "rotation-thread.hpp"
#include "session.hpp"

#include <pthread.h>
#include <stdbool.h>

struct timer_thread_parameters {
	lttng::sessiond::rotation_thread_timer_queue *rotation_thread_job_queue;
};

int timer_signal_init(void);

/* Start a session's rotation pending check timer (one-shot mode). */
int timer_session_rotation_pending_check_start(struct ltt_session *session,
					       unsigned int interval_us);
/* Stop a session's rotation pending check timer. */
int timer_session_rotation_pending_check_stop(ltt_session& session);

/* Start a session's rotation schedule timer. */
int timer_session_rotation_schedule_timer_start(struct ltt_session *session,
						unsigned int interval_us);
/* Stop a session's rotation schedule timer. */
int timer_session_rotation_schedule_timer_stop(struct ltt_session *session);

bool launch_timer_thread(struct timer_thread_parameters *timer_thread_parameters);

#endif /* SESSIOND_TIMER_H */
