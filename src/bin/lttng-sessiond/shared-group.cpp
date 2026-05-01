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

#include <climits>
#include <cstdint>
#include <limits>

namespace {

/*
 * Resolve the (min, max) bounds enforced by `value_type` for
 * saturation in `shared_group::increment`.
 */
struct value_bounds {
	std::int64_t min;
	std::int64_t max;
};

value_bounds
bounds_for(lttng::sessiond::config::map_channel_configuration::value_type_t value_type) noexcept
{
	using value_type_t = lttng::sessiond::config::map_channel_configuration::value_type_t;

	switch (value_type) {
	case value_type_t::SIGNED_INT_32:
		return { static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()),
			 static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max()) };
	case value_type_t::SIGNED_INT_64:
		return { std::numeric_limits<std::int64_t>::min(),
			 std::numeric_limits<std::int64_t>::max() };
	case value_type_t::SIGNED_INT_MAX:
		return sizeof(void *) == sizeof(std::uint32_t) ?
			value_bounds{
				static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::min()),
				static_cast<std::int64_t>(std::numeric_limits<std::int32_t>::max())
			} :
			value_bounds{ std::numeric_limits<std::int64_t>::min(),
				      std::numeric_limits<std::int64_t>::max() };
	}

	abort();
}

} /* namespace */

namespace lttng {
namespace sessiond {
namespace map {

shared_group::shared_group(const config::map_channel_configuration& configuration) :
	_configuration(configuration)
{
}

const config::map_channel_configuration& shared_group::configuration() const noexcept
{
	return _configuration;
}

void shared_group::increment(std::uint64_t index, std::int64_t delta)
{
	const auto bounds = bounds_for(_configuration.value_type);

	const std::lock_guard<std::mutex> guard(_lock);
	auto& el = _by_index[index];

	/*
	 * Saturating signed addition. Detect both overflow directions
	 * before applying the delta, then clamp; any clamp sticks the
	 * relevant sticky bit.
	 */
	if (delta > 0 && el.value > bounds.max - delta) {
		el.value = bounds.max;
		el.overflow = true;
	} else if (delta < 0 && el.value < bounds.min - delta) {
		el.value = bounds.min;
		el.underflow = true;
	} else {
		el.value += delta;
	}
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
