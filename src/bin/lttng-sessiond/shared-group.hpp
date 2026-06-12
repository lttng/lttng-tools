/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_SHARED_GROUP_HPP
#define LTTNG_SESSIOND_SHARED_GROUP_HPP

#include "map-group.hpp"

#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace map {

/*
 * Sessiond-only sibling group inside every map_channel.
 *
 * Two responsibilities:
 *
 *   1. Receive sessiond-executed `incr-value` bumps from the action
 *      executor.
 *   2. Receive drains from per-PID `ust::map_group`s whose owning app
 *      has exited, gated by the channel's `dead_group_policy`.
 *
 * Operates on indices, not strings. The map channel's `key_registry`
 * resolves strings up front.
 *
 * Saturation arithmetic uses the channel value-type's bounds and records
 * overflow / underflow as sticky bits on each element.
 */
class shared_group final : public group {
public:
	explicit shared_group(const config::map_channel_configuration& configuration);

	~shared_group() override = default;
	shared_group(const shared_group&) = delete;
	shared_group(shared_group&&) = delete;
	shared_group& operator=(const shared_group&) = delete;
	shared_group& operator=(shared_group&&) = delete;

	const config::map_channel_configuration& configuration() const noexcept;

	/*
	 * Add `delta` to the accumulator at `index`, saturating at the
	 * channel value-type's bounds. Saturation is recorded as a
	 * sticky overflow / underflow bit on the element.
	 */
	void increment(std::uint64_t index, std::int64_t delta);

	/* group interface. */
	element_value aggregate_element(std::uint64_t index) const override;
	void
	for_each_partition(const std::function<void(const partition_id&)>& visitor) const override;
	element_value read_element(std::uint64_t index,
				   const partition_id& partition) const override;
	void clear_element(std::uint64_t index) override;

	void clear() noexcept;
	std::size_t size() const noexcept;
	bool is_empty() const noexcept;

private:
	struct element {
		std::int64_t value = 0;
		bool overflow = false;
		bool underflow = false;
	};

	const config::map_channel_configuration& _configuration;
	mutable std::mutex _lock;
	std::unordered_map<std::uint64_t, element> _by_index;
};

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_SHARED_GROUP_HPP */
