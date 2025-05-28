/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/consumer/metadata-switch-timer-task.hpp>
#include <common/ust-consumer/ust-consumer.hpp>

void lttng::consumer::metadata_switch_timer_task::_run(lttng::scheduling::absolute_time current_time
						       [[maybe_unused]]) noexcept
{
	LTTNG_ASSERT(!_channel.is_deleted);

	if (_channel.switch_timer_error) {
		return;
	}

	DBG_FMT("Metadata switch timer task executing: channel_name=`{}`, channel_key={}",
		_channel.name,
		_channel.key);

	const auto request_ret = lttng_ustconsumer_request_metadata(
		_channel, _sessiond_metadata_socket, _consumer_error_socket_fd, true, 1);
	if (request_ret < 0) {
		_channel.switch_timer_error = 1;
	}
}