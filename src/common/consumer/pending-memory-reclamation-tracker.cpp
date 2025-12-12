/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "pending-memory-reclamation-tracker.hpp"

#include <common/consumer/consumer.hpp>
#include <common/error.hpp>
#include <common/pthread-lock.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/unix.hpp>

#include <cstring>
#include <vector>

namespace lttng {
namespace consumerd {

pending_memory_reclamation_tracker the_pending_memory_reclamation_tracker;

void pending_memory_reclamation_tracker::set_error_socket(protected_socket& error_socket) noexcept
{
	_error_socket = &error_socket;
}

void pending_memory_reclamation_tracker::set_scheduler(
	lttng::scheduling::scheduler& scheduler) noexcept
{
	_scheduler = &scheduler;
}

void pending_memory_reclamation_tracker::register_stream(std::uint64_t memory_reclaim_request_token)
{
	const std::lock_guard<std::mutex> lock(_lock);

	auto it = _pending_stream_counts.find(memory_reclaim_request_token);
	if (it == _pending_stream_counts.end()) {
		_pending_stream_counts.emplace(memory_reclaim_request_token, 1);
		DBG_FMT("Registered first stream for memory reclaim request token: token={}",
			memory_reclaim_request_token);
	} else {
		it->second++;
		DBG_FMT("Registered stream for memory reclaim request token: token={}, pending_count={}",
			memory_reclaim_request_token,
			it->second);
	}
}

void pending_memory_reclamation_tracker::stream_completed(
	const lttng_consumer_stream& stream, std::uint64_t memory_reclaim_request_token)
{
	bool operation_completed = false;

	{
		const std::lock_guard<std::mutex> lock(_lock);

		auto it = _pending_stream_counts.find(memory_reclaim_request_token);
		if (it == _pending_stream_counts.end()) {
			ERR_FMT("Stream completed for unknown memory reclaim request token: token={}",
				memory_reclaim_request_token);
			return;
		}

		it->second--;
		DBG_FMT("Stream completed for memory reclaim request token: token={}, remaining_count={}",
			memory_reclaim_request_token,
			it->second);

		if (it->second == 0) {
			_pending_stream_counts.erase(it);
			operation_completed = true;
		}
	}

	if (operation_completed) {
		_send_completion_notification(memory_reclaim_request_token);
		auto channel = stream.chan;
		if (channel->memory_reclaim_timer_task) {
			DBG_FMT("Resuming memory reclaim timer task for channel: session_id={}, "
				"channel_name={}, channel_key={}",
				channel->session_id,
				channel->name,
				channel->key);
			_scheduler->schedule(channel->memory_reclaim_timer_task,
					     std::chrono::steady_clock::now() +
						     channel->memory_reclaim_timer_task->period());
		}
	}
}

void pending_memory_reclamation_tracker::complete_if_no_pending_streams(
	std::uint64_t memory_reclaim_request_token)
{
	{
		const std::lock_guard<std::mutex> lock(_lock);

		const auto it = _pending_stream_counts.find(memory_reclaim_request_token);
		if (it != _pending_stream_counts.end()) {
			/* Streams are pending, completion will be sent when they complete. */
			DBG_FMT("Streams pending for memory reclaim request token, skipping immediate completion: "
				"token={}, pending_count={}",
				memory_reclaim_request_token,
				it->second);
			return;
		}
	}

	/* No streams pending, send completion immediately. */
	DBG_FMT("No streams pending for memory reclaim request token, sending immediate completion: token={}",
		memory_reclaim_request_token);
	_send_completion_notification(memory_reclaim_request_token);
}

void pending_memory_reclamation_tracker::_send_completion_notification(
	std::uint64_t memory_reclaim_request_token)
{
	if (!_error_socket) {
		ERR_FMT("Cannot send memory reclaim completion notification: error socket not set, token={}",
			memory_reclaim_request_token);
		return;
	}

	DBG_FMT("Sending memory reclaim completion notification: token={}, success=1",
		memory_reclaim_request_token);

	const lttcomm_consumer_error_msg_memory_reclaim_complete_notification payload = {
		.memory_reclaim_request_token = memory_reclaim_request_token,
		.success = 1,
	};

	const lttcomm_consumer_error_msg_header header = {
		.msg_type =
			static_cast<uint8_t>(LTTNG_CONSUMER_ERROR_MSG_TYPE_MEMORY_RECLAIM_COMPLETE),
		.size = sizeof(payload),
	};

	std::vector<uint8_t> buffer;
	buffer.resize(sizeof(header) + sizeof(payload));
	memcpy(buffer.data(), &header, sizeof(header));
	memcpy(buffer.data() + sizeof(header), &payload, sizeof(payload));

	const lttng::pthread::lock_guard socket_lock(_error_socket->lock);

	const auto send_ret =
		lttcomm_send_unix_sock(_error_socket->fd, buffer.data(), buffer.size());
	if (send_ret < 0) {
		PERROR("Failed to send memory reclamation completion notification");
		return;
	} else if (send_ret != buffer.size()) {
		ERR_FMT("Message truncated while sending memory reclamation completion notification: "
			"expected_size={}, actual_size={}",
			buffer.size(),
			send_ret);
		return;
	}

	DBG_FMT("Sent memory reclamation completion notification: token={}",
		memory_reclaim_request_token);
}

} /* namespace consumerd */
} /* namespace lttng */
