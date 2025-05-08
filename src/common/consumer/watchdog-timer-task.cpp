/*
 * SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/consumer/watchdog-timer-task.hpp>
#include <common/pthread-lock.hpp>
#include <common/urcu.hpp>
#include <common/ust-consumer/ust-consumer.hpp>

#include <set>

namespace {
void notify_sessiond_about_reclaimed_owner_ids(protected_socket& consumer_error_socket,
					       const std::set<uint32_t>& reclaimed_owner_ids)
{
	DBG_FMT("Notifying sessiond about owner reclamations: count={}",
		reclaimed_owner_ids.size());

	if (reclaimed_owner_ids.size() == 0) {
		return;
	}

	std::vector<uint32_t> payload_data;
	std::copy(reclaimed_owner_ids.begin(),
		  reclaimed_owner_ids.end(),
		  std::back_inserter(payload_data));

	/*
	 * It is impossible to have more than 2^32 reclamations since there are
	 * only 2^32 possible IDs.
	 */
	LTTNG_ASSERT(payload_data.size() <= UINT32_MAX);

	const struct lttcomm_consumer_error_msg_owner_reclaim_notification payload {
		.length = static_cast<uint32_t>(payload_data.size()),
	};

	const struct lttcomm_consumer_error_msg_header header = {
		.msg_type = static_cast<uint8_t>(
			LTTNG_CONSUMER_ERROR_MSG_TYPE_OWNER_RECLAIM_NOTIFICATION),
		.size = static_cast<uint64_t>(sizeof(payload) + sizeof(uint32_t) * payload.length),
	};

	const lttng::pthread::lock_guard consumer_error_socket_lock(consumer_error_socket.lock);

	int send_ret = lttcomm_send_unix_sock(consumer_error_socket.fd, &header, sizeof(header));
	if (send_ret < 0) {
		PERROR("Communication error occurred while "
		       "sending reclamation of owners");
		return;
	} else if (send_ret != sizeof(header)) {
		ERR_FMT("Header truncated while sending reclamation of owners: "
			"expected_size={} actual_size={}",
			sizeof(header),
			send_ret);
		return;
	}

	send_ret = lttcomm_send_unix_sock(consumer_error_socket.fd, &payload, sizeof(payload));
	if (send_ret < 0) {
		PERROR("Communication error occurred while "
		       "sending reclamation of owners");
		return;
	} else if (send_ret != sizeof(payload)) {
		ERR_FMT("Payload truncated while sending reclamation of owners: "
			"expected_size={} actual_size={}",
			sizeof(payload),
			send_ret);
		return;
	}

	send_ret = lttcomm_send_unix_sock(consumer_error_socket.fd,
					  payload_data.data(),
					  payload_data.size() * sizeof(uint32_t));
	if (send_ret < 0) {
		PERROR("Communication error occurred while "
		       "sending reclamation of owners");
		return;
	} else if (send_ret != (payload_data.size() * sizeof(uint32_t))) {
		ERR_FMT("Payload data truncated while sending reclamation of owners: "
			"expected_size={}, actual_size={}",
			payload_data.size() * sizeof(uint32_t),
			send_ret);
		return;
	}
}

/* Execute action on a buffer-stall watchdog timer. */
ssize_t stall_watchdog_timer(struct lttng_consumer_channel& channel,
			     protected_socket& consumer_error_socket)

{
	LTTNG_ASSERT(consumer_error_socket.fd >= 0);
	LTTNG_ASSERT(channel.type != CONSUMER_CHANNEL_TYPE_METADATA);

	std::set<uint32_t> reclaimed_owner_ids;
	size_t observed_count;

	if (lttng_ustconsumer_fixup_stalled_channel(
		    &channel, reclaimed_owner_ids, observed_count) == 0) {
		notify_sessiond_about_reclaimed_owner_ids(consumer_error_socket,
							  reclaimed_owner_ids);
		return observed_count;
	}

	return -1;
}
} /* namespace */

void lttng::consumer::watchdog_timer_task::_run(lttng::scheduling::absolute_time current_time
						[[maybe_unused]]) noexcept
{
	(void) stall_watchdog_timer(_channel, _consumer_error_socket);
}

ssize_t lttng::consumer::watchdog_timer_task::run() noexcept
{
	const std::lock_guard<std::mutex> lock(_mutex);

	return stall_watchdog_timer(_channel, _consumer_error_socket);
}
