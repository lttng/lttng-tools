/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2012 - David Goulet <dgoulet@efficios.com>
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

#ifndef CONSUMER_TIMER_H
#define CONSUMER_TIMER_H

#include <pthread.h>

#include "consumer.h"

#define LTTNG_CONSUMER_SIG_SWITCH	SIGRTMIN + 10
#define LTTNG_CONSUMER_SIG_TEARDOWN	SIGRTMIN + 11
#define LTTNG_CONSUMER_SIG_LIVE		SIGRTMIN + 12
#define LTTNG_CONSUMER_SIG_MONITOR	SIGRTMIN + 13
#define LTTNG_CONSUMER_SIG_EXIT		SIGRTMIN + 14

#define CLOCKID CLOCK_MONOTONIC

/*
 * Handle timer teardown race wrt memory free of private data by consumer
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

void consumer_timer_switch_start(struct lttng_consumer_channel *channel,
		unsigned int switch_timer_interval_us);
void consumer_timer_switch_stop(struct lttng_consumer_channel *channel);
void consumer_timer_live_start(struct lttng_consumer_channel *channel,
		unsigned int live_timer_interval_us);
void consumer_timer_live_stop(struct lttng_consumer_channel *channel);
int consumer_timer_monitor_start(struct lttng_consumer_channel *channel,
		unsigned int monitor_timer_interval_us);
int consumer_timer_monitor_stop(struct lttng_consumer_channel *channel);
void *consumer_timer_thread(void *data);
int consumer_signal_init(void);

int consumer_flush_kernel_index(struct lttng_consumer_stream *stream);
int consumer_flush_ust_index(struct lttng_consumer_stream *stream);

int consumer_timer_thread_get_channel_monitor_pipe(void);
int consumer_timer_thread_set_channel_monitor_pipe(int fd);

#endif /* CONSUMER_TIMER_H */
