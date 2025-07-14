/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_MEMORY_RECLAIM_TIMER_TASK_HPP
#define LTTNG_CONSUMER_MEMORY_RECLAIM_TIMER_TASK_HPP

#include <common/consumer/consumer.hpp>
#include <common/scheduler.hpp>

#include <chrono>

namespace lttng {
namespace consumer {
class memory_reclaim_timer_task : public lttng::scheduling::periodic_task {
public:
	memory_reclaim_timer_task() = delete;

	memory_reclaim_timer_task(const memory_reclaim_timer_task&) = delete;
	memory_reclaim_timer_task(memory_reclaim_timer_task&&) = delete;
	memory_reclaim_timer_task& operator=(const memory_reclaim_timer_task&) = delete;
	memory_reclaim_timer_task& operator=(memory_reclaim_timer_task&&) = delete;

	~memory_reclaim_timer_task() override = default;

	explicit memory_reclaim_timer_task(lttng::scheduling::duration_ns period,
					   lttng_consumer_channel& channel,
					   std::chrono::microseconds age_limit) noexcept :
		periodic_task(
			period,
			fmt::format(
				"Memory reclaim: channel_name=`{}`, key={}, session_id={}, age_limit_us={}",
				channel.name,
				channel.key,
				channel.session_id,
				age_limit.count())),
		_channel(channel),
		_age_limit(age_limit)
	{
	}

protected:
	void _run(lttng::scheduling::absolute_time current_time) noexcept override;

private:
	lttng_consumer_channel& _channel;
	const std::chrono::microseconds _age_limit;
};
} /* namespace consumer */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_MEMORY_RECLAIM_TIMER_TASK_HPP */
