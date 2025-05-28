/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_LIVE_TIMER_TASK_HPP
#define LTTNG_CONSUMER_LIVE_TIMER_TASK_HPP

#include <common/consumer/consumer.hpp>
#include <common/scheduler.hpp>

namespace lttng {
namespace consumer {
class live_timer_task : public lttng::scheduling::periodic_task {
public:
	using flush_index_cb = int (*)(struct lttng_consumer_stream *);

	live_timer_task() = delete;

	live_timer_task(const live_timer_task&) = delete;
	live_timer_task(live_timer_task&&) = delete;
	live_timer_task& operator=(const live_timer_task&) = delete;
	live_timer_task& operator=(live_timer_task&&) = delete;

	~live_timer_task() override = default;

	explicit live_timer_task(lttng::scheduling::duration_ns period,
				 lttng_consumer_channel& channel) noexcept :
		periodic_task(period), _channel(channel)
	{
	}

protected:
	void _run(lttng::scheduling::absolute_time current_time) noexcept override;

private:
	lttng_consumer_channel& _channel;
};
} /* namespace consumer */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_LIVE_TIMER_TASK_HPP */