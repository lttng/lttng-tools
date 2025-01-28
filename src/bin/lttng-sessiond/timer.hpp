/*
 * SPDX-FileCopyrightText: 2017 Julien Desfossez <jdesfossez@efficios.com>
 * SPDX-FileCopyrightText: 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

int timer_signal_init();

/* Start a session's rotation pending check timer (one-shot mode). */
int timer_session_rotation_pending_check_start(const ltt_session::locked_ref& session,
					       unsigned int interval_us);
/* Stop a session's rotation pending check timer. */
int timer_session_rotation_pending_check_stop(const ltt_session::locked_ref& session);

/* Start a session's rotation schedule timer. */
int timer_session_rotation_schedule_timer_start(const ltt_session::locked_ref& session,
						unsigned int interval_us);
/* Stop a session's rotation schedule timer. */
int timer_session_rotation_schedule_timer_stop(const ltt_session::locked_ref& session);

bool launch_timer_thread(struct timer_thread_parameters *timer_thread_parameters);

#endif /* SESSIOND_TIMER_H */
