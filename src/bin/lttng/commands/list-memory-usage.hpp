/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_LIST_MEMORY_USAGE_HPP
#define LTTNG_LIST_MEMORY_USAGE_HPP

#include <common/ctl/memory.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/channel.h>
#include <lttng/domain.h>
#include <lttng/stream-info.h>

#include <cstdint>

namespace lttng {
namespace cli {
namespace memory_usage {

/*
 * RAII wrapper for channel memory usage data that automatically manages
 * the lifecycle of lttng_data_stream_info_sets.
 */
class channel_memory_usage_info_sets {
public:
	/* channel_memory_usage_data takes ownership of ds_info_sets */
	explicit channel_memory_usage_info_sets(const lttng_data_stream_info_sets *ds_info_sets);

	~channel_memory_usage_info_sets();

	channel_memory_usage_info_sets(const channel_memory_usage_info_sets&) = delete;
	channel_memory_usage_info_sets& operator=(const channel_memory_usage_info_sets&) = delete;
	channel_memory_usage_info_sets(channel_memory_usage_info_sets&&) = default;
	channel_memory_usage_info_sets& operator=(channel_memory_usage_info_sets&& other) = delete;

	const lttng_data_stream_info_sets *data_stream_info_sets() const noexcept
	{
		return _ds_info_sets.get();
	}

	const unsigned int data_stream_info_sets_count;
	const std::uint64_t total_memory_usage;

private:
	data_stream_info_sets_cuptr _ds_info_sets;
};

/*
 * Factory function to retrieve memory usage data for a channel.
 *
 * Throws on error.
 */
channel_memory_usage_info_sets get_channel_memory_usage(const char *session_name,
							lttng_channel *channel,
							lttng_domain_type domain);

/* Calculate total memory usage across all data stream info sets. */
std::uint64_t compute_total_memory_usage(lttng_channel *channel,
					 const lttng_data_stream_info_sets *ds_info_sets,
					 unsigned int ds_info_sets_count);

/* Calculate memory usage for a single data stream info set. */
std::uint64_t compute_set_memory_usage(lttng_channel *channel,
				       const lttng_data_stream_info_set *ds_info_set,
				       unsigned int ds_info_set_index);

} /* namespace memory_usage */
} /* namespace cli */
} /* namespace lttng */

#endif /* LTTNG_LIST_MEMORY_USAGE_HPP */
