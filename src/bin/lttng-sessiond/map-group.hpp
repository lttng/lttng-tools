/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MAP_GROUP_HPP
#define LTTNG_SESSIOND_MAP_GROUP_HPP

#include <common/exception.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <functional>
#include <string>

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
class group {
public:
	group() = default;
	virtual ~group() = default;

	group(const group&) = delete;
	group& operator=(const group&) = delete;

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
	 * group.
	 */
	virtual element_value read_element(std::uint64_t index,
					   const partition_id& partition) const = 0;

	virtual void clear_element(std::uint64_t index) = 0;

protected:
	/*
	 * Move construction / assignment are protected and defaulted so that
	 * derived types can opt into being moveable while callers cannot
	 * slice an `group` reference.
	 */
	group(group&&) noexcept = default;
	group& operator=(group&&) noexcept = default;
};

namespace exceptions {

/*
 * @class element_index_out_of_range
 * @brief Thrown when a map element operation targets an index that lies
 * outside the configured dimension(s) of the map.
 *
 * Corresponds to the tracer reporting that the requested element does
 * not exist (e.g. EOVERFLOW from the kernel counter ABI).
 */
class element_index_out_of_range : public lttng::out_of_range {
public:
	explicit element_index_out_of_range(const std::string& msg,
					    const lttng::source_location& source_location_) :
		lttng::out_of_range(msg, source_location_)
	{
	}
};

/*
 * @class element_invalid_cpu
 * @brief Thrown when a per-element read receives a CPU argument that is
 * incompatible with the counter's allocation mode or the system topology.
 *
 * This covers omitting a CPU on a per-CPU-only counter, supplying a CPU
 * on a per-channel-only counter, and supplying a CPU outside the system's
 * possible CPU range.
 */
class element_invalid_cpu : public lttng::invalid_argument_error {
public:
	explicit element_invalid_cpu(const std::string& msg,
				     const lttng::source_location& source_location_) :
		lttng::invalid_argument_error(msg, source_location_)
	{
	}
};

} /* namespace exceptions */

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#define LTTNG_THROW_MAP_ELEMENT_INDEX_OUT_OF_RANGE(msg)                     \
	throw lttng::sessiond::map::exceptions::element_index_out_of_range( \
		msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_MAP_ELEMENT_INVALID_CPU(msg) \
	throw lttng::sessiond::map::exceptions::element_invalid_cpu(msg, LTTNG_SOURCE_LOCATION())

#endif /* LTTNG_SESSIOND_MAP_GROUP_HPP */
