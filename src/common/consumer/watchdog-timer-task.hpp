/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_WATCHDOG_TIMER_TASK_HPP
#define LTTNG_CONSUMER_WATCHDOG_TIMER_TASK_HPP

#include <common/consumer/consumer.hpp>
#include <common/scheduler.hpp>

namespace lttng {
namespace consumer {
class watchdog_timer_task : public lttng::scheduling::periodic_task {
public:
	watchdog_timer_task() = delete;

	watchdog_timer_task(const watchdog_timer_task&) = delete;
	watchdog_timer_task(watchdog_timer_task&&) = delete;
	watchdog_timer_task& operator=(const watchdog_timer_task&) = delete;
	watchdog_timer_task& operator=(watchdog_timer_task&&) = delete;

	~watchdog_timer_task() override = default;

	explicit watchdog_timer_task(lttng::scheduling::duration_ns period,
				     lttng_consumer_channel& channel,
				     protected_socket& consumer_error_socket) noexcept :
		periodic_task(period,
			      fmt::format("Watchdog: channel_name=`{}`, key={}, session_id={}",
					  channel.name,
					  channel.key,
					  channel.session_id)),
		_channel(channel),
		_consumer_error_socket(consumer_error_socket)
	{
		LTTNG_ASSERT(_consumer_error_socket.fd >= 0);
	}

	ssize_t run() noexcept;

protected:
	void _run(lttng::scheduling::absolute_time current_time) noexcept override;

private:
	lttng_consumer_channel& _channel;
	protected_socket& _consumer_error_socket;
};
} /* namespace consumer */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_WATCHDOG_TIMER_TASK_HPP */
