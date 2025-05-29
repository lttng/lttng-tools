/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_MONITOR_TIMER_TASK_HPP
#define LTTNG_CONSUMER_MONITOR_TIMER_TASK_HPP

#include <common/consumer/consumer.hpp>
#include <common/scheduler.hpp>

namespace lttng {
namespace consumer {
class monitor_timer_task : public lttng::scheduling::periodic_task {
public:
	monitor_timer_task() = delete;

	monitor_timer_task(const monitor_timer_task&) = delete;
	monitor_timer_task(monitor_timer_task&&) = delete;
	monitor_timer_task& operator=(const monitor_timer_task&) = delete;
	monitor_timer_task& operator=(monitor_timer_task&&) = delete;

	~monitor_timer_task() override = default;

	explicit monitor_timer_task(lttng::scheduling::duration_ns period,
				    lttng_consumer_channel& channel,
				    int channel_monitor_pipe) noexcept :
		periodic_task(period,
			      fmt::format("Monitor: channel_name=`{}`, key={}, session_id={}",
					  channel.name,
					  channel.key,
					  channel.session_id)),
		_channel(channel),
		_channel_monitor_pipe(channel_monitor_pipe)
	{
		LTTNG_ASSERT(_channel_monitor_pipe >= 0);
	}

protected:
	void _run(lttng::scheduling::absolute_time current_time) noexcept override;

private:
	lttng_consumer_channel& _channel;
	const int _channel_monitor_pipe;
};
} /* namespace consumer */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_MONITOR_TIMER_TASK_HPP */