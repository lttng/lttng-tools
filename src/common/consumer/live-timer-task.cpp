/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/consumer/live-timer-task.hpp>
#include <common/urcu.hpp>

namespace {
int check_stream(lttng_consumer_stream& stream)
{
	int ret;

	/*
	 * While holding the stream mutex, try to take a snapshot, if it
	 * succeeds, it means that data is ready to be sent, just let the data
	 * thread handle that. Otherwise, if the snapshot returns EAGAIN, it
	 * means that there is no data to read after the flush, so we can
	 * safely send the empty index.
	 *
	 * Doing a trylock and checking if waiting on metadata if
	 * trylock fails. Bail out of the stream is indeed waiting for
	 * metadata to be pushed. Busy wait on trylock otherwise.
	 */
	for (;;) {
		ret = pthread_mutex_trylock(&stream.lock);
		switch (ret) {
		case 0:
			break; /* We have the lock. */
		case EBUSY:
			pthread_mutex_lock(&stream.metadata_timer_lock);
			if (stream.waiting_on_metadata) {
				ret = 0;
				stream.missed_metadata_flush = true;
				pthread_mutex_unlock(&stream.metadata_timer_lock);
				goto end; /* Bail out. */
			}
			pthread_mutex_unlock(&stream.metadata_timer_lock);
			/* Try again. */
			caa_cpu_relax();
			continue;
		default:
			ERR("Unexpected pthread_mutex_trylock error %d", ret);
			ret = -1;
			goto end;
		}
		break;
	}

	ret = stream.read_subbuffer_ops.send_live_beacon(stream);
	pthread_mutex_unlock(&stream.lock);
end:
	return ret;
}
} /* namespace */

void lttng::consumer::live_timer_task::_run(lttng::scheduling::absolute_time current_time
					    [[maybe_unused]]) noexcept
{
	LTTNG_ASSERT(!_channel.is_deleted);

	if (_channel.switch_timer_error) {
		return;
	}

	DBG_FMT("Live timer task executing: channel_name=`{}`, channel_key={}",
		_channel.name,
		_channel.key);

	const auto *stream_per_chan_id_ht = the_consumer_data.stream_per_chan_id_ht;

	for (auto *stream : lttng::urcu::lfht_filtered_iteration_adapter<
		     lttng_consumer_stream,
		     decltype(lttng_consumer_stream::node_channel_id),
		     &lttng_consumer_stream::node_channel_id,
		     std::uint64_t>(*stream_per_chan_id_ht->ht,
				    &_channel.key,
				    stream_per_chan_id_ht->hash_fct(&_channel.key, lttng_ht_seed),
				    stream_per_chan_id_ht->match_fct)) {
		const auto ret = check_stream(*stream);
		if (ret < 0) {
			return;
		}
	}
}