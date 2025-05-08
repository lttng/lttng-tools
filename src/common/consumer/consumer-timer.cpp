/*
 * SPDX-FileCopyrightText: 2012 Julien Desfossez <julien.desfossez@efficios.com>
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/consumer/consumer-stream.hpp>
#include <common/consumer/consumer-testpoint.hpp>
#include <common/consumer/consumer-timer.hpp>
#include <common/consumer/live-timer-task.hpp>
#include <common/consumer/metadata-switch-timer-task.hpp>
#include <common/consumer/monitor-timer-task.hpp>
#include <common/consumer/watchdog-timer-task.hpp>
#include <common/kernel-consumer/kernel-consumer.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/urcu.hpp>
#include <common/ust-consumer/ust-consumer.hpp>

#include <inttypes.h>

namespace {
bool is_userspace_consumer() noexcept
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return true;
	case LTTNG_CONSUMER_KERNEL:
	case LTTNG_CONSUMER_UNKNOWN:
		return false;
	default:
		abort();
	}
}
} /* namespace */

static int the_channel_monitor_pipe = -1;

/* Start the channel's periodic metadata switching task. */
void consumer_timer_switch_start(struct lttng_consumer_channel *channel,
				 unsigned int switch_timer_interval_us,
				 protected_socket& sessiond_metadata_socket,
				 protected_socket& consumer_error_socket,
				 lttng::scheduling::scheduler& scheduler)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);

	if (!is_userspace_consumer() || switch_timer_interval_us == 0) {
		return;
	}

	try {
		channel->metadata_switch_timer_task =
			std::make_shared<lttng::consumer::metadata_switch_timer_task>(
				std::chrono::microseconds(switch_timer_interval_us),
				*channel,
				sessiond_metadata_socket,
				consumer_error_socket);

		scheduler.schedule(channel->live_timer_task,
				   std::chrono::steady_clock::now() +
					   std::chrono::microseconds(switch_timer_interval_us));
	} catch (const std::bad_alloc& e) {
		ERR_FMT("Failed to allocate memory for metadata switch timer task: {}", e.what());
		return;
	}
}

/* Stop the channel's metadata switching task. */
void consumer_timer_switch_stop(struct lttng_consumer_channel *channel)
{
	LTTNG_ASSERT(channel);

	channel->metadata_switch_timer_task->cancel();
	channel->metadata_switch_timer_task.reset();
}

/* Start the channel's periodic "live mode" management task. */
void consumer_timer_live_start(struct lttng_consumer_channel *channel,
			       unsigned int live_timer_interval_us,
			       lttng::scheduling::scheduler& scheduler)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);

	if (live_timer_interval_us == 0) {
		/* No creation needed; not an error. */
		return;
	}

	try {
		channel->live_timer_task = std::make_shared<lttng::consumer::live_timer_task>(
			std::chrono::microseconds(live_timer_interval_us), *channel);

		scheduler.schedule(channel->live_timer_task,
				   std::chrono::steady_clock::now() +
					   std::chrono::microseconds(live_timer_interval_us));
	} catch (const std::bad_alloc& e) {
		ERR_FMT("Failed to allocate memory for live timer task: {}: channel_name=`{}`, key={}, session_id={}",
			e.what(),
			channel->name,
			channel->key,
			channel->session_id);
		return;
	}
}

/* Stop the channel's "live mode" management task. */
void consumer_timer_live_stop(struct lttng_consumer_channel *channel)
{
	LTTNG_ASSERT(channel);
	if (!channel->live_timer_task) {
		return;
	}

	/* Cancel the live timer task if it is scheduled. */
	channel->live_timer_task->cancel();
	channel->live_timer_task.reset();
}

/*
 * Set the channel's monitoring timer.
 *
 * Returns a negative value on error, 0 if a timer was created, and
 * a positive value if no timer was created (not an error).
 */
int consumer_timer_monitor_start(struct lttng_consumer_channel *channel,
				 unsigned int monitor_timer_interval_us,
				 lttng::scheduling::scheduler& scheduler)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);
	LTTNG_ASSERT(!channel->monitor_timer_task);

	if (monitor_timer_interval_us == 0) {
		/* No creation needed; not an error. */
		return 0;
	}

	try {
		channel->monitor_timer_task = std::make_shared<lttng::consumer::monitor_timer_task>(
			std::chrono::microseconds(monitor_timer_interval_us),
			*channel,
			consumer_timer_thread_get_channel_monitor_pipe());

		scheduler.schedule(channel->monitor_timer_task,
				   std::chrono::steady_clock::now() +
					   std::chrono::microseconds(monitor_timer_interval_us));
	} catch (const std::bad_alloc& e) {
		ERR_FMT("Failed to allocate memory for live timer task: {}: channel_name=`{}`, key={}, session_id={}",
			e.what(),
			channel->name,
			channel->key,
			channel->session_id);
		return -1;
	}

	return 0;
}

/*
 * Stop the channel's monitoring task.
 */
int consumer_timer_monitor_stop(struct lttng_consumer_channel *channel)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->monitor_timer_task);

	/* Cancel the monitor timer task if it is scheduled. */
	channel->monitor_timer_task->cancel();
	channel->monitor_timer_task.reset();
	return 0;
}

/*
 * Set the channel's buffer-stall watchdog timer.
 *
 * Returns a negative value on error, 0 if a timer was created, and
 * a positive value if no timer was created (not an error).
 */
int consumer_timer_stall_watchdog_start(struct lttng_consumer_channel *channel,
					protected_socket& consumer_error_socket,
					unsigned int watchdog_timer_interval_us,
					lttng::scheduling::scheduler& scheduler)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);
	LTTNG_ASSERT(!channel->stall_watchdog_timer_task);
	LTTNG_ASSERT(channel->subbuffer_count);

	try {
		/*
		 * Always create the watchdog timer task even if the timer is
		 * set to an interval of zero. This allows running the task when
		 * reaching a quiescent state for the channel, e.g. when the
		 * associated session is stopped or destroyed.
		 */
		channel->stall_watchdog_timer_task =
			std::make_shared<lttng::consumer::watchdog_timer_task>(
				std::chrono::microseconds(watchdog_timer_interval_us),
				*channel,
				consumer_error_socket);
		if (watchdog_timer_interval_us != 0) {
			scheduler.schedule(
				channel->stall_watchdog_timer_task,
				std::chrono::steady_clock::now() +
					std::chrono::microseconds(watchdog_timer_interval_us));
		}

	} catch (const std::bad_alloc& e) {
		ERR_FMT("Failed to allocate memory for live timer task: {}: channel_name=`{}`, key={}, session_id={}",
			e.what(),
			channel->name,
			channel->key,
			channel->session_id);
		return -1;
	}

	return 0;
}

/*
 * Stop and delete the channel's watchdog timer.
 */
int consumer_timer_stall_watchdog_stop(struct lttng_consumer_channel *channel)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->stall_watchdog_timer_task);

	/* Cancel the watchdog timer task if it is scheduled. */
	channel->stall_watchdog_timer_task->cancel();
	channel->stall_watchdog_timer_task.reset();
	return 0;
}

int consumer_timer_thread_get_channel_monitor_pipe()
{
	return uatomic_read(&the_channel_monitor_pipe);
}

int consumer_timer_thread_set_channel_monitor_pipe(int fd)
{
	int ret;

	ret = uatomic_cmpxchg(&the_channel_monitor_pipe, -1, fd);
	if (ret != -1) {
		ret = -1;
		goto end;
	}
	ret = 0;
end:
	return ret;
}
