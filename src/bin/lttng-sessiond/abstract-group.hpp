/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_ABSTRACT_GROUP_HPP
#define LTTNG_SESSIOND_ABSTRACT_GROUP_HPP

#include <vendor/optional.hpp>

#include <cstdint>
#include <functional>

namespace lttng {
namespace sessiond {
namespace map {

/*
 * The value of a single counter element as reported by a group.
 */
struct element_value {
	std::int64_t value;
	bool overflow;
	bool underflow;
};

/*
 * Identifies one partition (map) of a group: the CPU id for the
 * tracer-backed groups, which keep one map per CPU. The shared group has
 * no per-partition decomposition: its single map is identified by an
 * unset id.
 */
using partition_id = nonstd::optional<unsigned int>;

/*
 * Common per-index interface exposed by every group inside a
 * map_channel: the tracer-backed groups (`modules::map_group`,
 * `ust::map_group`) and the sessiond-only `shared_group`.
 *
 * Iteration over elements is intentionally absent here: it only makes
 * sense in the context of the channel's `key_registry`, which knows
 * which indices have been allocated. Callers iterate via
 * `map_channel::for_each_element_of(group, visitor)` instead.
 */
class abstract_group {
public:
	abstract_group() = default;
	virtual ~abstract_group() = default;

	abstract_group(const abstract_group&) = delete;
	abstract_group& operator=(const abstract_group&) = delete;

	virtual element_value aggregate_element(std::uint64_t index) const = 0;

	/*
	 * Invoke `visitor` once per partition (map) of the group, in the
	 * order the public API serializes them. A group with no
	 * per-partition fan-out (e.g. the shared group) reports a single
	 * partition with an unset id.
	 */
	virtual void
	for_each_partition(const std::function<void(const partition_id&)>& visitor) const = 0;

	/*
	 * Read the element at `index` on the partition identified by
	 * `partition`, which must come from for_each_partition on this
	 * group. This is the per-partition counterpart of aggregate_element,
	 * which collapses every partition into a single total.
	 */
	virtual element_value read_element(std::uint64_t index,
					   const partition_id& partition) const = 0;

	virtual void clear_element(std::uint64_t index) = 0;

protected:
	/*
	 * Move construction / assignment are protected and defaulted so that
	 * derived types can opt into being moveable while callers cannot
	 * slice an `abstract_group` reference.
	 */
	abstract_group(abstract_group&&) noexcept = default;
	abstract_group& operator=(abstract_group&&) noexcept = default;
};

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_ABSTRACT_GROUP_HPP */
