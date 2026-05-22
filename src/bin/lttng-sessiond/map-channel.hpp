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

#include <common/hash-combine.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

struct lttng_event_rule;
struct lttng_action;

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace map {

class abstract_group;

/*
 * Identifies a counter-event rule registered against a map channel by the
 * (event_rule, increment-map-value action) pair of the trigger that produced
 * it. Both pointers are stable for the trigger's registered lifetime, which
 * matches the window during which the orchestrator holds rule state.
 */
using event_rule_action_key = std::pair<const lttng_event_rule *, const lttng_action *>;

struct event_rule_action_key_hash {
	std::size_t operator()(const event_rule_action_key& key) const noexcept
	{
		auto seed = std::hash<const lttng_event_rule *>{}(key.first);
		seed = lttng::utils::hash_combine(seed,
						  std::hash<const lttng_action *>{}(key.second));
		return seed;
	}
};

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

	/*
	 * A weak observer of the channel's registry, for consumers that
	 * run outside the recording session lock and must therefore guard
	 * against the channel being torn down concurrently. The
	 * application-notification thread resolves a key-registration
	 * request to a registry through this observer: it upgrades the
	 * weak_ptr with `lock()`, which both keeps the registry alive for
	 * the resolution and reports (by returning empty) that the owning
	 * channel has been destroyed.
	 *
	 * Returns an empty observer for INDEX-keyed channels (no
	 * registry); see the constructor's note on `has_registry()`.
	 */
	std::weak_ptr<key_registry> registry_observer() const noexcept;

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

	/*
	 * Allocate the next user_token for a rule about to be registered on
	 * this channel. The token is a monotonic 64-bit counter that is never
	 * recycled: at 2^64 distinct tokens, recycling on rule removal would
	 * add complexity without buying anything useful.
	 */
	std::uint64_t allocate_user_token() noexcept;

protected:
	std::uint64_t _next_user_token = 0;

private:
	const config::map_channel_configuration& _configuration;
	key_registry::sptr _registry;
	shared_group _shared;
};

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MAP_CHANNEL_HPP */
