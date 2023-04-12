/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CONSUMER_TIMER_H
#define CONSUMER_TIMER_H

#include "consumer.hpp"

#include <pthread.h>

#define LTTNG_CONSUMER_SIG_SWITCH   ((SIGRTMIN + 10))
#define LTTNG_CONSUMER_SIG_TEARDOWN ((SIGRTMIN + 11))
#define LTTNG_CONSUMER_SIG_LIVE	    ((SIGRTMIN + 12))
#define LTTNG_CONSUMER_SIG_MONITOR  ((SIGRTMIN + 13))
#define LTTNG_CONSUMER_SIG_EXIT	    ((SIGRTMIN + 14))

#define CLOCKID CLOCK_MONOTONIC

/*
 * Handle timer teardown race wrt memory free of private data by consumer
 * signals are handled by a single thread, which permits a synchronization
 * point between handling of each signal. Internal lock ensures mutual
 * exclusion.
 */
struct timer_signal_data {
	pthread_t tid; /* thread id managing signals */
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
int consumer_signal_init();

int consumer_flush_kernel_index(struct lttng_consumer_stream *stream);
int consumer_flush_ust_index(struct lttng_consumer_stream *stream);

int consumer_timer_thread_get_channel_monitor_pipe();
int consumer_timer_thread_set_channel_monitor_pipe(int fd);

#endif /* CONSUMER_TIMER_H */
