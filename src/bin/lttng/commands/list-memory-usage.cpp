/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "list-memory-usage.hpp"

#include <common/ctl/format.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>

#include <lttng/stream-info.h>

#include <vendor/fmt/format.h>

namespace lttng {
namespace cli {
namespace memory_usage {

channel_memory_usage_info_sets::channel_memory_usage_info_sets(
	const lttng_data_stream_info_sets *ds_info_sets) :
	data_stream_info_sets_count([ds_info_sets]() -> unsigned int {
		unsigned int count = 0;
		const auto status = lttng_data_stream_info_sets_get_count(ds_info_sets, &count);

		if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			LTTNG_THROW_ERROR("Failed to retrieve count of data stream info sets");
		}

		return count;
	}()),
	total_memory_usage(
		compute_total_memory_usage(nullptr, ds_info_sets, data_stream_info_sets_count)),
	_ds_info_sets(ds_info_sets)
{
}

channel_memory_usage_info_sets::~channel_memory_usage_info_sets() = default;

channel_memory_usage_info_sets
get_channel_memory_usage(const char *session_name, lttng_channel *channel, lttng_domain_type domain)
{
	const lttng_data_stream_info_sets *ds_info_sets = nullptr;

	const auto ds_info_sets_status = lttng_channel_get_data_stream_info_sets(
		session_name, channel->name, domain, &ds_info_sets);

	switch (ds_info_sets_status) {
	case LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK:
		break;
	case LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_UNSUPPORTED_DOMAIN:
		LTTNG_THROW_UNSUPPORTED_ERROR(fmt::format(
			"Retrieving data stream info sets is unsupported for domain: session_name=`{}`, domain={}, channel_name=`{}`",
			session_name,
			domain,
			channel->name));
		break;
	case LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_INVALID_PARAMETER:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Invalid parameter when retrieving data stream info sets: session_name=`{}`, domain={}, channel_name=`{}`",
			session_name,
			domain,
			channel->name));
		break;
	default:
		LTTNG_THROW_ERROR(fmt::format(
			"Failed to retrieve data stream info sets of channel: session_name=`{}`, domain={}, channel_name=`{}`",
			session_name,
			domain,
			channel->name));
		break;
	}

	LTTNG_ASSERT(ds_info_sets);
	return channel_memory_usage_info_sets(ds_info_sets);
}

std::uint64_t compute_total_memory_usage(lttng_channel *channel,
					 const lttng_data_stream_info_sets *ds_info_sets,
					 unsigned int ds_info_sets_count)
{
	std::uint64_t total_mem_bytes = 0;

	for (unsigned int i = 0; i < ds_info_sets_count; i++) {
		const lttng_data_stream_info_set *ds_info_set = nullptr;

		const auto status =
			lttng_data_stream_info_sets_get_at_index(ds_info_sets, i, &ds_info_set);
		if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			/* Item access should not return NONE; this is a fatal error. */
			if (channel) {
				ERR_FMT("Failed to retrieve data stream info set #{} of channel `{}`",
					i,
					channel->name);
			} else {
				ERR_FMT("Failed to retrieve data stream info set #{}", i);
			}

			return 0;
		}

		total_mem_bytes += compute_set_memory_usage(channel, ds_info_set, i);
	}

	return total_mem_bytes;
}

std::uint64_t compute_set_memory_usage(lttng_channel *channel,
				       const lttng_data_stream_info_set *ds_info_set,
				       unsigned int ds_info_set_index)
{
	unsigned int ds_info_count = 0;
	std::uint64_t set_mem_bytes = 0;

	auto status = lttng_data_stream_info_set_get_count(ds_info_set, &ds_info_count);
	if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
		/* Item access should not return NONE; this is a fatal error. */
		if (channel) {
			ERR_FMT("Failed to retrieve data stream info count of set #{} of channel `{}`",
				ds_info_set_index,
				channel->name);
		} else {
			ERR_FMT("Failed to retrieve data stream info count of set #{}",
				ds_info_set_index);
		}

		return 0;
	}

	for (unsigned int ds_info_i = 0; ds_info_i < ds_info_count; ds_info_i++) {
		const lttng_data_stream_info *ds_info = nullptr;
		std::uint64_t mem_bytes = 0;

		status = lttng_data_stream_info_set_get_at_index(ds_info_set, ds_info_i, &ds_info);
		if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			/* Item access should not return NONE; this is a fatal error. */
			if (channel) {
				ERR_FMT("Failed to retrieve data stream info #{} of set #{} of channel `{}`",
					ds_info_i,
					ds_info_set_index,
					channel->name);
			} else {
				ERR_FMT("Failed to retrieve data stream info #{} of set #{}",
					ds_info_i,
					ds_info_set_index);
			}

			return 0;
		}

		status = lttng_data_stream_info_get_memory_usage(ds_info, &mem_bytes);
		if (status != LTTNG_DATA_STREAM_INFO_STATUS_OK) {
			/* Memory usage should always be available; NONE is unexpected here */
			if (channel) {
				ERR_FMT("Failed to retrieve memory usage of data stream info #{} of set {} of channel `{}`",
					ds_info_i,
					ds_info_set_index,
					channel->name);
			} else {
				ERR_FMT("Failed to retrieve memory usage of data stream info #{} of set {}",
					ds_info_i,
					ds_info_set_index);
			}

			return 0;
		}

		set_mem_bytes += mem_bytes;
	}

	return set_mem_bytes;
}

} /* namespace memory_usage */
} /* namespace cli */
} /* namespace lttng */
