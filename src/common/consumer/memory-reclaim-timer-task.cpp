/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/consumer/consumer-stream.hpp>
#include <common/consumer/memory-reclaim-timer-task.hpp>
#include <common/pthread-lock.hpp>
#include <common/urcu.hpp>
#include <common/ust-consumer/ust-consumer.hpp>

namespace {
} /* namespace */

void lttng::consumer::memory_reclaim_timer_task::_run(lttng::scheduling::absolute_time current_time
						      [[maybe_unused]]) noexcept
{
	try {
		const lttng::pthread::lock_guard channel_lock(_channel.lock);
		DBG_FMT("Reclaiming channel memory: key={}, channel_name=`{}`",
			_channel.key,
			_channel.name);

		const bool require_consumed = _channel.event_loss_mode ==
			CONSUMER_CHANNEL_EVENT_LOSS_MODE_DISCARD_EVENTS;

		std::uint64_t bytes_reclaimed = 0;
		if (_channel.monitor) {
			const lttng::urcu::read_lock_guard read_lock;
			for (auto *stream : lttng::urcu::lfht_filtered_iteration_adapter<
				     lttng_consumer_stream,
				     decltype(lttng_consumer_stream::node_channel_id),
				     &lttng_consumer_stream::node_channel_id,
				     std::uint64_t>(
				     *the_consumer_data.stream_per_chan_id_ht->ht,
				     &_channel.key,
				     the_consumer_data.stream_per_chan_id_ht->hash_fct(
					     &_channel.key, lttng_ht_seed),
				     the_consumer_data.stream_per_chan_id_ht->match_fct)) {
				const lttng::pthread::lock_guard stream_lock(stream->lock);

				if (cds_lfht_is_node_deleted(&stream->node.node)) {
					continue;
				}

				bytes_reclaimed += consumer_stream_reclaim_memory(
					*stream, _age_limit, require_consumed);
			}
		} else {
			for (auto *stream :
			     lttng::urcu::list_iteration_adapter<lttng_consumer_stream,
								 &lttng_consumer_stream::send_node>(
				     _channel.streams.head)) {
				const lttng::pthread::lock_guard stream_lock(stream->lock);

				bytes_reclaimed += consumer_stream_reclaim_memory(
					*stream, _age_limit, require_consumed);
			}
		}

		DBG_FMT("Reclaimed memory from channel: channel_name=`{}`, key={}, bytes_reclaimed={}",
			_channel.name,
			_channel.key,
			bytes_reclaimed);
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to reclaim channel memory: channel_name=`{}`, key={}, error=`{}`",
			_channel.name,
			_channel.key,
			ex.what());
	}
}
