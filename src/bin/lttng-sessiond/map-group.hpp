/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MAP_GROUP_HPP
#define LTTNG_SESSIOND_MAP_GROUP_HPP

#include <common/make-unique.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace lttng {
namespace sessiond {
namespace map {

/*
 * The value of a single counter element as reported by the tracer.
 */
struct element_value {
	std::int64_t value;
	bool overflow;
	bool underflow;
};

/*
 * A map::group represents the per-CPU counter partition backing a single
 * map channel configuration for a given: uid+abi in per-UID UST mode,
 * an app in per-PID UST mode, or the recording session
 * (or event-notifier group) in the kernel.
 *
 * The MapHandleType template parameter carries the domain-specific
 * per-CPU handle (ust_object_data or fd).
 *
 * The tracer-side counter handle (kernel counter fd, UST daemon
 * counter) is not part of the base; it is owned by the domain-
 * specific map_group subclass.
 *
 * Domain-specific map_groups inherit from this base.
 */
template <typename MapHandleType>
class group {
public:
	/*
	 * A single map inside the group.
	 *
	 * When `cpu_id` is set, the map represents the counter partition
	 * for that specific CPU. When unset, the map is shared across
	 * CPUs (per-channel allocation) and carries no CPU identity.
	 */
	struct map {
		map(const nonstd::optional<unsigned int>& cpu_id_, MapHandleType handle_) :
			cpu_id(cpu_id_), handle(std::move(handle_))
		{
		}

		virtual ~map() = default;

		map(map&&) = default;
		map& operator=(map&&) = default;
		map(const map&) = delete;
		map& operator=(const map&) = delete;

		const nonstd::optional<unsigned int> cpu_id;
		MapHandleType handle;
	};

	using uptr = std::unique_ptr<group>;

	group() = default;
	virtual ~group() = default;

	group(const group&) = delete;
	group(group&&) = delete;
	group& operator=(const group&) = delete;
	group& operator=(group&&) = delete;

	virtual void add_map(nonstd::optional<unsigned int> cpu_id, MapHandleType handle)
	{
		_maps.emplace_back(lttng::make_unique<map>(cpu_id, std::move(handle)));
	}

	const std::vector<std::unique_ptr<map>>& maps() const noexcept
	{
		return _maps;
	}

	std::vector<std::unique_ptr<map>>& maps() noexcept
	{
		return _maps;
	}

	unsigned int map_count() const noexcept
	{
		return _maps.size();
	}

protected:
	/*
	 * Insert a domain-specific map sub-type. Derived map_group
	 * classes use this to add extended map objects that carry
	 * additional per-CPU housekeeping.
	 */
	void _add_map(std::unique_ptr<map> m)
	{
		_maps.emplace_back(std::move(m));
	}

	std::vector<std::unique_ptr<map>> _maps;
};

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MAP_GROUP_HPP */
