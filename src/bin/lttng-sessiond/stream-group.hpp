/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_STREAM_GROUP_HPP
#define LTTNG_SESSIOND_STREAM_GROUP_HPP

#include <common/exception.hpp>
#include <common/make-unique.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace lttng {
namespace sessiond {

/*
 * A stream_group represents the streams (ring buffer instances) backing a
 * single channel within a recording session (or, in the future, an
 * aggregation map).
 *
 * In per-CPU allocation mode, the group contains one stream per CPU. In
 * per-channel allocation mode, it contains a single stream. This distinction
 * is transparent to users of the group — they simply iterate over its streams.
 *
 * The group tracks the consumer-side key used to reference this channel with
 * the consumer daemon.
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
 * Domain-specific stream groups inherit from this base and may extend the
 * nested stream type with additional housekeeping fields.
 */
template <typename StreamHandleType>
class stream_group {
public:
	/*
	 * A single stream (ring buffer instance) within the group.
	 *
	 * Each stream is identified by a CPU index. In per-channel allocation
	 * mode, the single stream uses cpu index 0.
	 *
	 * Derived stream_group classes may extend this type to carry
	 * domain-specific per-stream state and insert instances through
	 * the protected _add_stream() method.
	 */
	struct stream {
		stream(unsigned int cpu_index, StreamHandleType handle_) :
			cpu(cpu_index), handle(std::move(handle_))
		{
		}

		virtual ~stream() = default;

		stream(stream&&) = default;
		stream& operator=(stream&&) = default;
		stream(const stream&) = delete;
		stream& operator=(const stream&) = delete;

		const unsigned int cpu;
		StreamHandleType handle;
	};

	using uptr = std::unique_ptr<stream_group>;

	explicit stream_group(uint64_t consumer_key) : _consumer_stream_group_key(consumer_key)
	{
	}

	virtual ~stream_group() = default;
	stream_group(const stream_group&) = delete;
	stream_group(stream_group&&) = delete;
	stream_group& operator=(const stream_group&) = delete;
	stream_group& operator=(stream_group&&) = delete;

	/* Stream management. */
	void add_stream(unsigned int cpu, StreamHandleType handle)
	{
		_streams.emplace_back(lttng::make_unique<stream>(cpu, std::move(handle)));
	}

	const std::vector<std::unique_ptr<stream>>& streams() const noexcept
	{
		return _streams;
	}

	std::vector<std::unique_ptr<stream>>& streams() noexcept
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

protected:
	/*
	 * Insert a domain-specific stream sub-type. Derived stream_group
	 * classes use this to add extended stream objects that carry
	 * additional per-stream housekeeping fields.
	 */
	void _add_stream(std::unique_ptr<stream> s)
	{
		_streams.emplace_back(std::move(s));
	}

	std::vector<std::unique_ptr<stream>> _streams;

private:
	const uint64_t _consumer_stream_group_key;
};

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_STREAM_GROUP_HPP */
