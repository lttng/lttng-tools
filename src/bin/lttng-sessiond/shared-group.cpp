/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "map-channel-configuration.hpp"
#include "shared-group.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>

#include <cstdint>

namespace lttng {
namespace sessiond {
namespace map {

shared_group::shared_group(const config::map_channel_configuration& configuration) :
	/*
	 * The shared group is the sessiond-side aggregator that sums the
	 * contributions of dead per-PID groups of any width; it is always a
	 * 64-bit accumulator so that summing narrower groups can't silently
	 * lose magnitude.
	 */
	group(config::map_channel_configuration::value_type_t::SIGNED_INT_64),
	_configuration(configuration)
{
}

const config::map_channel_configuration& shared_group::configuration() const noexcept
{
	return _configuration;
}

void shared_group::increment(std::uint64_t index, std::int64_t delta)
{
	const std::lock_guard<std::mutex> guard(_lock);
	auto& el = _by_index[index];

	/*
	 * Modular (wrap-around) signed addition, matching the kernel and user
	 * space tracer counters.
	 */
	const auto old_value = el.value;
	const auto new_value = static_cast<std::int64_t>(static_cast<std::uint64_t>(old_value) +
							 static_cast<std::uint64_t>(delta));

	if (delta > 0 && new_value < old_value) {
		el.overflow = true;
	} else if (delta < 0 && new_value > old_value) {
		el.underflow = true;
	}

	el.value = new_value;
}

element_value shared_group::aggregate_element(std::uint64_t index) const
{
	const std::lock_guard<std::mutex> guard(_lock);
	const auto it = _by_index.find(index);

	if (it == _by_index.end()) {
		return element_value{ 0, false, false };
	}

	return element_value{ it->second.value, it->second.overflow, it->second.underflow };
}

void shared_group::for_each_partition(const std::function<void(const partition_id&)>& visitor) const
{
	/* The shared group is a single, partition-less map. */
	visitor(nonstd::nullopt);
}

element_value shared_group::read_element(std::uint64_t index, const partition_id& partition) const
{
	LTTNG_ASSERT(!partition);
	return aggregate_element(index);
}

void shared_group::clear_element(std::uint64_t index)
{
	const std::lock_guard<std::mutex> guard(_lock);

	_by_index.erase(index);
}

void shared_group::clear() noexcept
{
	const std::lock_guard<std::mutex> guard(_lock);

	_by_index.clear();
}

std::size_t shared_group::size() const noexcept
{
	const std::lock_guard<std::mutex> guard(_lock);

	return _by_index.size();
}

bool shared_group::is_empty() const noexcept
{
	const std::lock_guard<std::mutex> guard(_lock);

	return _by_index.empty();
}

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */
