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
#include <common/testpoint/testpoint.hpp>
#include <common/unix.hpp>

#include <algorithm>
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
	/* Tests break on this point to observe that a request deferred a stream. */
	TESTPOINT("memory_reclaim_stream_deferred");

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

void pending_memory_reclamation_tracker::begin_request(std::uint64_t memory_reclaim_request_token)
{
	const std::lock_guard<std::mutex> lock(_lock);

	/*
	 * Hold a reference on the request for the duration of its setup. This is
	 * released by end_request() and ensures the count can not reach zero (which
	 * would complete the request and resume its suspended timers) while the caller
	 * is still registering the channels and streams the request touches.
	 */
	_pending_stream_counts[memory_reclaim_request_token]++;
	DBG_FMT("Began memory reclaim request: token={}", memory_reclaim_request_token);
}

void pending_memory_reclamation_tracker::register_suspended_channel(
	std::uint64_t memory_reclaim_request_token, lttng_consumer_channel& channel)
{
	/* Tests break on this point to count the channels a request suspends. */
	TESTPOINT("memory_reclaim_channel_suspended");

	const std::lock_guard<std::mutex> lock(_lock);

	_suspended_channels_per_token[memory_reclaim_request_token].emplace_back(channel);
	DBG_FMT("Registered suspended channel for memory reclaim request token: token={}, channel_name=`{}`, channel_key={}",
		memory_reclaim_request_token,
		channel.name,
		channel.key);
}

void pending_memory_reclamation_tracker::stream_completed(std::uint64_t memory_reclaim_request_token)
{
	_decrement_and_maybe_complete(memory_reclaim_request_token);
}

void pending_memory_reclamation_tracker::end_request(std::uint64_t memory_reclaim_request_token)
{
	_decrement_and_maybe_complete(memory_reclaim_request_token);
}

void pending_memory_reclamation_tracker::abort_request(
	std::uint64_t memory_reclaim_request_token) noexcept
{
	{
		const std::lock_guard<std::mutex> lock(_lock);
		_pending_stream_counts.erase(memory_reclaim_request_token);
	}

	/*
	 * Resume the suspended timer tasks so automatic reclamation keeps running even
	 * though the request failed. This is best-effort: swallow any exception to honour
	 * the noexcept contract expected on this error path.
	 */
	try {
		_resume_suspended_channels(memory_reclaim_request_token);
	} catch (...) {
	}
}

void pending_memory_reclamation_tracker::channel_removed(const lttng_consumer_channel& channel)
{
	const std::lock_guard<std::mutex> lock(_lock);

	for (auto& token_channels : _suspended_channels_per_token) {
		auto& channels = token_channels.second;
		channels.erase(
			std::remove_if(channels.begin(),
				       channels.end(),
				       [&channel](const lttng_consumer_channel& suspended_channel) {
					       return &suspended_channel == &channel;
				       }),
			channels.end());
	}
}

void pending_memory_reclamation_tracker::_decrement_and_maybe_complete(
	std::uint64_t memory_reclaim_request_token)
{
	bool operation_completed = false;

	{
		const std::lock_guard<std::mutex> lock(_lock);

		auto it = _pending_stream_counts.find(memory_reclaim_request_token);
		if (it == _pending_stream_counts.end()) {
			ERR_FMT("Completion reported for unknown memory reclaim request token: token={}",
				memory_reclaim_request_token);
			return;
		}

		it->second--;
		DBG_FMT("Memory reclaim request token pending count decremented: token={}, remaining_count={}",
			memory_reclaim_request_token,
			it->second);

		if (it->second == 0) {
			_pending_stream_counts.erase(it);
			operation_completed = true;
		}
	}

	if (operation_completed) {
		_send_completion_notification(memory_reclaim_request_token);
		_resume_suspended_channels(memory_reclaim_request_token);
	}
}

void pending_memory_reclamation_tracker::_resume_suspended_channels(
	std::uint64_t memory_reclaim_request_token)
{
	/*
	 * Resume the suspended channels' timer tasks while holding `_lock`, which
	 * channel_removed() also acquires. consumer_del_channel() drops a channel from the
	 * set (through channel_removed()) before it stops the channel's reclaim timer task
	 * and eventually frees the channel, so a channel still in the set here can not be
	 * torn down concurrently: it is safe to dereference and reschedule under the lock.
	 */
	const std::lock_guard<std::mutex> lock(_lock);

	auto it = _suspended_channels_per_token.find(memory_reclaim_request_token);
	if (it == _suspended_channels_per_token.end()) {
		return;
	}

	for (lttng_consumer_channel& channel : it->second) {
		_resume_channel_timer(channel);
	}

	_suspended_channels_per_token.erase(it);
}

void pending_memory_reclamation_tracker::_resume_channel_timer(lttng_consumer_channel& channel)
{
	if (!channel.memory_reclaim_timer_task) {
		return;
	}

	/*
	 * Only resume a timer task that was suspended (cancelled). This avoids scheduling
	 * the same task twice should it already have been resumed.
	 */
	if (!channel.memory_reclaim_timer_task->canceled()) {
		return;
	}

	DBG_FMT("Resuming memory reclaim timer task for channel: session_id={}, channel_name=`{}`, channel_key={}",
		channel.session_id,
		channel.name,
		channel.key);
	_scheduler->schedule(channel.memory_reclaim_timer_task,
			     std::chrono::steady_clock::now() +
				     channel.memory_reclaim_timer_task->period());
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
