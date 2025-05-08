
/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_METADATA_SWITCH_TIMER_TASK_HPP
#define LTTNG_CONSUMER_METADATA_SWITCH_TIMER_TASK_HPP

#include <common/consumer/consumer.hpp>
#include <common/scheduler.hpp>

namespace lttng {
namespace consumer {
class metadata_switch_timer_task : public lttng::scheduling::periodic_task {
public:
	using flush_index_cb = int (*)(struct lttng_consumer_stream *);

	metadata_switch_timer_task() = delete;

	metadata_switch_timer_task(const metadata_switch_timer_task&) = delete;
	metadata_switch_timer_task(metadata_switch_timer_task&&) = delete;
	metadata_switch_timer_task& operator=(const metadata_switch_timer_task&) = delete;
	metadata_switch_timer_task& operator=(metadata_switch_timer_task&&) = delete;

	~metadata_switch_timer_task() override = default;

	explicit metadata_switch_timer_task(lttng::scheduling::duration_ns period,
					    lttng_consumer_channel& channel,
					    protected_socket& sessiond_metadata_socket,
					    protected_socket& consumer_error_socket) noexcept :
		periodic_task(period,
			      fmt::format("Metadata switch: key={}, session_id={}",
					  channel.key,
					  channel.session_id)),
		_channel(channel),
		_sessiond_metadata_socket(sessiond_metadata_socket),
		_consumer_error_socket(consumer_error_socket)
	{
	}

protected:
	/*
	 * Beware: should *never* take a mutex also held while consumer_timer_switch_stop() is
	 * called. It would result in deadlocks.
	 */
	void _run(lttng::scheduling::absolute_time current_time) noexcept override;

private:
	lttng_consumer_channel& _channel;
	protected_socket& _sessiond_metadata_socket;
	protected_socket& _consumer_error_socket;
};
} /* namespace consumer */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_METADATA_SWITCH_TIMER_TASK_HPP */
