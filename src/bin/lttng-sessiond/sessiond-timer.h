/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
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

#define LTTNG_SESSIOND_SIG_TEARDOWN		SIGRTMIN + 10
#define LTTNG_SESSIOND_SIG_EXIT			SIGRTMIN + 11
#define LTTNG_SESSIOND_SIG_ROTATE_PENDING	SIGRTMIN + 12

#define CLOCKID CLOCK_MONOTONIC

/*
 * Handle timer teardown race wrt memory free of private data by sessiond
 * signals are handled by a single thread, which permits a synchronization
 * point between handling of each signal. Internal lock ensures mutual
 * exclusion.
 */
struct timer_signal_data {
	pthread_t tid;	/* thread id managing signals */
	int setup_done;
	int qs_done;
	pthread_mutex_t lock;
};

struct timer_thread_parameters {
	struct rotation_thread_timer_queue *rotation_timer_queue;
};

struct sessiond_rotation_timer {
	uint64_t session_id;
	unsigned int signal;
	struct cds_list_head head; /* List member in struct rotation_thread_timer_queue */
} LTTNG_PACKED;

void *sessiond_timer_thread(void *data);
int sessiond_timer_signal_init(void);

int sessiond_timer_rotate_pending_start(struct ltt_session *session, unsigned int
		interval_us);
void sessiond_timer_rotate_pending_stop(struct ltt_session *session);

#endif /* SESSIOND_TIMER_H */
