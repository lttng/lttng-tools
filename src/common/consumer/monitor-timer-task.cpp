/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/consumer/monitor-timer-task.hpp>
#include <common/kernel-consumer/kernel-consumer.hpp>
#include <common/pthread-lock.hpp>
#include <common/urcu.hpp>
#include <common/ust-consumer/ust-consumer.hpp>

namespace {
using sample_positions_cb = int (*)(struct lttng_consumer_stream *);
using get_consumed_cb = int (*)(struct lttng_consumer_stream *, unsigned long *);
using get_produced_cb = int (*)(struct lttng_consumer_stream *, unsigned long *);

int sample_channel_positions(lttng_consumer_channel& channel,
			     uint64_t *_highest_use,
			     uint64_t *_lowest_use,
			     uint64_t *_total_consumed,
			     sample_positions_cb sample,
			     get_consumed_cb get_consumed,
			     get_produced_cb get_produced) noexcept
{
	int ret = 0;
	bool empty_channel = true;
	uint64_t high = 0, low = UINT64_MAX;

	*_total_consumed = 0;

	const lttng::pthread::lock_guard channel_lock(channel.lock);
	for (auto& stream : channel.get_streams()) {
		empty_channel = false;

		const lttng::pthread::lock_guard stream_lock(stream.lock);
		if (cds_lfht_is_node_deleted(&stream.node.node)) {
			continue;
		}

		ret = sample(&stream);
		if (ret) {
			ERR("Failed to take buffer position snapshot in monitor timer (ret = %d)",
			    ret);
			goto end;
		}

		unsigned long produced, consumed, usage;
		ret = get_consumed(&stream, &consumed);
		if (ret) {
			ERR("Failed to get buffer consumed position in monitor timer");
			goto end;
		}
		ret = get_produced(&stream, &produced);
		if (ret) {
			ERR("Failed to get buffer produced position in monitor timer");
			goto end;
		}

		usage = produced - consumed;
		high = (usage > high) ? usage : high;
		low = (usage < low) ? usage : low;

		/*
		 * We don't use consumed here for 2 reasons:
		 *  - output_written takes into account the padding written in the
		 *    tracefiles when we stop the session;
		 *  - the consumed position is not the accurate representation of what
		 *    was extracted from a buffer in overwrite mode.
		 */
		*_total_consumed += stream.output_written;
	}

	*_highest_use = high;
	*_lowest_use = low;
end:
	if (empty_channel) {
		ret = -1;
	}

	return ret;
}
} /* namespace */

/* Sample and send channel buffering statistics to the session daemon. */
void lttng::consumer::monitor_timer_task::_run(lttng::scheduling::absolute_time current_time
					       [[maybe_unused]]) noexcept
{
	int ret;
	struct lttcomm_consumer_channel_monitor_msg msg = {
		.key = _channel.key,
		.session_id = _channel.session_id,
		.lowest = 0,
		.highest = 0,
		.consumed_since_last_sample = 0,
	};
	sample_positions_cb sample;
	get_consumed_cb get_consumed;
	get_produced_cb get_produced;
	uint64_t lowest = 0, highest = 0, total_consumed = 0;

	const lttng::pthread::lock_guard consumer_data_lock(the_consumer_data.lock);
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		sample = lttng_kconsumer_sample_snapshot_positions;
		get_consumed = lttng_kconsumer_get_consumed_snapshot;
		get_produced = lttng_kconsumer_get_produced_snapshot;
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		sample = lttng_ustconsumer_sample_snapshot_positions;
		get_consumed = lttng_ustconsumer_get_consumed_snapshot;
		get_produced = lttng_ustconsumer_get_produced_snapshot;
		break;
	default:
		abort();
	}

	ret = sample_channel_positions(
		_channel, &highest, &lowest, &total_consumed, sample, get_consumed, get_produced);
	if (ret) {
		return;
	}

	msg.highest = highest;
	msg.lowest = lowest;
	msg.consumed_since_last_sample =
		total_consumed - _channel.consumed_size_as_of_last_sample_sent;

	/*
	 * Writes performed here are assumed to be atomic which is only
	 * guaranteed for sizes < than PIPE_BUF.
	 */
	LTTNG_ASSERT(sizeof(msg) <= PIPE_BUF);

	do {
		ret = write(_channel_monitor_pipe, &msg, sizeof(msg));
	} while (ret == -1 && errno == EINTR);
	if (ret == -1) {
		if (errno == EAGAIN) {
			/* Not an error, the sample is merely dropped. */
			DBG("Channel monitor pipe is full; dropping sample for channel key = %" PRIu64,
			    _channel.key);
		} else {
			PERROR("write to the channel monitor pipe");
		}
	} else {
		DBG("Sent channel monitoring sample for channel key %" PRIu64
		    ", (highest = %" PRIu64 ", lowest = %" PRIu64 ")",
		    _channel.key,
		    msg.highest,
		    msg.lowest);
		_channel.consumed_size_as_of_last_sample_sent = total_consumed;
	}
}
