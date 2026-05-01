/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MAP_CHANNEL_HPP
#define LTTNG_SESSIOND_MAP_CHANNEL_HPP

#include "key-registry.hpp"
#include "shared-group.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace map {

class abstract_group;

/*
 * Per-channel runtime owned by the domain orchestrator. Aggregates the
 * channel's `key_registry`, its `shared_group`, and (in the domain
 * subclasses) its tracer-backed group(s).
 *
 * The base provides the registry / shared accessors and the
 * `for_each_element_of` helper that walks a group through the
 * channel's registered keys. Domain-specific group storage and
 * iteration live in the subclasses (`modules::map_channel`,
 * `ust::map_channel`).
 */
class map_channel {
public:
	using uptr = std::unique_ptr<map_channel>;

	/*
	 * Visitor signature for `for_each_element_of`. Invoked once per
	 * (key, index) pair registered on the channel, with the value
	 * read from the supplied group.
	 */
	using element_visitor = std::function<void(
		lttng::c_string_view key, std::uint64_t index, const element_value& value)>;

	/*
	 * `registry` may be null for INDEX-keyed channels: those
	 * channels reference indices directly and do not maintain a
	 * string registry. Callers that walk a group's elements via
	 * `for_each_element_of` therefore must check `has_registry()`
	 * before iterating.
	 */
	map_channel(const config::map_channel_configuration& configuration,
		    key_registry::uptr registry);

	virtual ~map_channel() = default;
	map_channel(const map_channel&) = delete;
	map_channel(map_channel&&) = delete;
	map_channel& operator=(const map_channel&) = delete;
	map_channel& operator=(map_channel&&) = delete;

	const config::map_channel_configuration& configuration() const noexcept;

	bool has_registry() const noexcept;

	key_registry& registry() noexcept;
	const key_registry& registry() const noexcept;

	shared_group& shared() noexcept;
	const shared_group& shared() const noexcept;

	/*
	 * Walk the channel's registry and emit
	 * `(key, index, group.aggregate_element(index))` for every key
	 * registered, in registry-determined order.
	 *
	 * Invoking this on an INDEX-keyed channel (no registry) throws,
	 * since iteration over flat indices is the caller's
	 * responsibility in that case.
	 */
	void for_each_element_of(const abstract_group& group, const element_visitor& visitor) const;

private:
	const config::map_channel_configuration& _configuration;
	key_registry::uptr _registry;
	shared_group _shared;
};

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MAP_CHANNEL_HPP */
