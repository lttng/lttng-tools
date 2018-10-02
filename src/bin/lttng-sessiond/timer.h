/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef SESSIOND_TIMER_H
#define SESSIOND_TIMER_H

#include <pthread.h>

#include "session.h"

struct timer_thread_parameters {
	struct rotation_thread_timer_queue *rotation_thread_job_queue;
};

int timer_signal_init(void);
void *timer_thread_func(void *data);

void timer_exit(void);

/* Start a session's rotation pending check timer (one-shot mode). */
int timer_session_rotation_pending_check_start(struct ltt_session *session,
		unsigned int interval_us);
/* Stop a session's rotation pending check timer. */
int timer_session_rotation_pending_check_stop(struct ltt_session *session);

/* Start a session's rotation schedule timer. */
int timer_session_rotation_schedule_timer_start(struct ltt_session *session,
		unsigned int interval_us);
/* Stop a session's rotation schedule timer. */
int timer_session_rotation_schedule_timer_stop(struct ltt_session *session);

#endif /* SESSIOND_TIMER_H */
