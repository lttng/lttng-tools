/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_ABSTRACT_GROUP_HPP
#define LTTNG_SESSIOND_ABSTRACT_GROUP_HPP

#include <cstdint>

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
