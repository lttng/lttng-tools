/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_STREAM_GROUP_HPP
#define LTTNG_SESSIOND_UST_STREAM_GROUP_HPP

#include "stream-group.hpp"
#include "ust-object-data.hpp"

#include <cstdint>

namespace lttng {
namespace sessiond {

namespace config {
class recording_channel_configuration;
} /* namespace config */

namespace ust {

class trace_class;
class stream_class;

/*
 * Runtime representation of a UST stream group: the ring buffer instances
 * backing a single channel configuration for a given uid+bitness or app.
 *
 * In per-UID mode, one stream_group exists per (channel_config, uid,
 * abi_bitness) combination. The first application with a matching
 * (uid, abi) creates the shared buffers; subsequent applications receive
 * duplicates of the channel and stream object handles.
 *
 * In per-PID mode, one stream_group exists per (channel_config, app).
 * Per-PID stream groups do not store streams centrally (they go directly
 * to the per-app channel). The stream_group still tracks the consumer key
 * and channel object handle.
 *
 * Extends the base stream_group (which manages the consumer key and stream
 * instances) with:
 *   - The UST channel object data (the "master" channel ABI handle from
 *     the consumer daemon).
 *   - A reference to the channel configuration from which this group was
 *     derived.
 *   - A reference to the trace_class that generates CTF metadata for this
 *     group's streams.
 *   - A direct reference to the stream_class (within the trace_class) that
 *     describes this channel's CTF schema.
 *   - A sent_to_consumer lifecycle flag.
 */
class stream_group final : public lttng::sessiond::stream_group<ust_object_data> {
public:
	explicit stream_group(uint64_t consumer_key,
			      ust_object_data channel_object,
			      const config::recording_channel_configuration& configuration,
			      ust::trace_class& trace_class,
			      ust::stream_class& stream_class);

	~stream_group() override = default;

	stream_group(stream_group&&) = delete;
	stream_group(const stream_group&) = delete;
	stream_group& operator=(stream_group&&) = delete;
	stream_group& operator=(const stream_group&) = delete;

	const config::recording_channel_configuration& configuration() const noexcept;

	ust::trace_class& get_trace_class() const noexcept;
	ust::stream_class& get_stream_class() const noexcept;

	const ust_object_data& channel_object() const noexcept;
	ust_object_data& channel_object() noexcept;

	/*
	 * Create a duplicate of the channel object data for sending to a
	 * newly-registered application. Used in per-UID mode where multiple
	 * apps share the same stream group.
	 */
	ust_object_data duplicate_channel_object() const;

	bool is_sent_to_consumer() const noexcept;
	void mark_sent_to_consumer() noexcept;

private:
	ust_object_data _channel_object;
	const config::recording_channel_configuration& _configuration;
	ust::trace_class& _trace_class;
	ust::stream_class& _stream_class;
	bool _sent_to_consumer = false;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_STREAM_GROUP_HPP */
