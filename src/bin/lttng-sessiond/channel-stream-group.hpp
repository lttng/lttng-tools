/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CHANNEL_STREAM_GROUP_HPP
#define LTTNG_SESSIOND_CHANNEL_STREAM_GROUP_HPP

#include <common/exception.hpp>
#include <common/make-unique.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace lttng {
namespace sessiond {

/*
 * A channel_stream_group represents the streams (ring buffer instances) backing
 * a single channel within a recording session (or, in the future, an
 * aggregation map).
 *
 * In per-CPU allocation mode, the group contains one stream per CPU. In
 * per-channel allocation mode, it contains a single stream. This distinction
 * is transparent to users of the group — they simply iterate over its streams.
 *
 * The group also tracks consumer-daemon lifecycle state: the consumer-side key
 * used to reference this channel and whether the channel has been registered
 * with the consumer daemon.
 *
 * The StreamHandleType template parameter carries the domain-specific resource
 * handle for each stream (ring buffer instance):
 *
 *   - Kernel domain: a file descriptor (or RAII wrapper thereof) obtained
 *     from the kernel tracer via ioctl.
 *
 *   - UST domain: a wrapper around the lttng_ust_abi_object_data pointer
 *     obtained from the consumer daemon after channel creation.
 *
 * The tracer-side channel handle (kernel channel fd, UST channel object
 * handle) is NOT part of the stream group — it is owned by the domain
 * orchestrator directly. The stream group is concerned with the consumer-facing
 * view: the streams that the consumer daemon reads from.
 *
 * Typical usage within an orchestrator:
 *
 *   // Kernel orchestrator creates a stream group after opening the channel.
 *   auto streams = lttng::make_unique<channel_stream_group<kernel_stream_fd>>(
 *       consumer_key);
 *
 *   // Add one stream per CPU (or one stream for per-channel allocation).
 *   for (auto cpu = 0u; cpu < nr_cpus; ++cpu) {
 *       auto stream_fd = kernel_open_stream(channel_fd, cpu);
 *       streams->add_stream(cpu, kernel_stream_fd(stream_fd));
 *   }
 *
 *   // Later, when starting the session, send to the consumer daemon.
 *   if (!streams->is_sent_to_consumer()) {
 *       consumer_send_channel(consumer, *streams);
 *       streams->mark_sent_to_consumer();
 *   }
 */
template <typename StreamHandleType>
class channel_stream_group final {
public:
	/*
	 * A single stream (ring buffer instance) within the group.
	 *
	 * Each stream is identified by a CPU index. In per-channel allocation
	 * mode, the single stream uses cpu index 0.
	 */
	struct stream {
		stream(unsigned int cpu_index, StreamHandleType handle_) :
			cpu(cpu_index), handle(std::move(handle_))
		{
		}

		const unsigned int cpu;
		StreamHandleType handle;
	};

	using uptr = std::unique_ptr<channel_stream_group>;

	explicit channel_stream_group(uint64_t consumer_key) :
		_consumer_stream_group_key(consumer_key)
	{
	}

	~channel_stream_group() = default;
	channel_stream_group(const channel_stream_group&) = delete;
	channel_stream_group(channel_stream_group&&) = delete;
	channel_stream_group& operator=(const channel_stream_group&) = delete;
	channel_stream_group& operator=(channel_stream_group&&) = delete;

	/* Stream management. */
	void add_stream(unsigned int cpu, StreamHandleType handle)
	{
		_streams.emplace_back(cpu, std::move(handle));
	}

	const std::vector<stream>& streams() const noexcept
	{
		return _streams;
	}

	std::vector<stream>& streams() noexcept
	{
		return _streams;
	}

	unsigned int stream_count() const noexcept
	{
		return _streams.size();
	}

	/* Consumer-daemon lifecycle. */
	uint64_t consumer_key() const noexcept
	{
		return _consumer_stream_group_key;
	}

private:
	const uint64_t _consumer_stream_group_key;
	std::vector<stream> _streams;
};

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_CHANNEL_STREAM_GROUP_HPP */
