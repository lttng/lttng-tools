/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CONSUMER_TIMER_H
#define CONSUMER_TIMER_H

#include "consumer.hpp"

#include <common/scheduler.hpp>

void consumer_timer_switch_start(struct lttng_consumer_channel *channel,
				 unsigned int switch_timer_interval_us,
				 protected_socket& sessiond_metadata_socket,
				 protected_socket& consumer_error_socket,
				 lttng::scheduling::scheduler& scheduler);
void consumer_timer_switch_stop(struct lttng_consumer_channel *channel);
void consumer_timer_live_start(struct lttng_consumer_channel *channel,
			       unsigned int live_timer_interval_us,
			       lttng::scheduling::scheduler& scheduler);
void consumer_timer_live_stop(struct lttng_consumer_channel *channel);
int consumer_timer_monitor_start(struct lttng_consumer_channel *channel,
				 unsigned int monitor_timer_interval_us,
				 lttng::scheduling::scheduler& scheduler);
int consumer_timer_monitor_stop(struct lttng_consumer_channel *channel);

int consumer_timer_stall_watchdog_start(struct lttng_consumer_channel *channel,
					protected_socket& consumer_error_socket,
					unsigned int watchdog_timer_interval_us,
					lttng::scheduling::scheduler& scheduler);
int consumer_timer_stall_watchdog_stop(struct lttng_consumer_channel *channel);

int consumer_timer_memory_reclaim_start(lttng_consumer_channel& channel,
					std::chrono::microseconds max_age,
					lttng::scheduling::scheduler& scheduler);
void consumer_timer_memory_reclaim_stop(lttng_consumer_channel *channel);

int consumer_timer_thread_get_channel_monitor_pipe();
int consumer_timer_thread_set_channel_monitor_pipe(int fd);

#endif /* CONSUMER_TIMER_H */
