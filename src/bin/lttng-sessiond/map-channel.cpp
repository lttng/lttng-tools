/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "map-channel-configuration.hpp"
#include "map-channel.hpp"
#include "map-group.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>

#include <utility>

namespace lttng {
namespace sessiond {
namespace map {

map_channel::map_channel(const config::map_channel_configuration& configuration,
			 key_registry::uptr registry) :
	_configuration(configuration), _registry(std::move(registry)), _shared(configuration)
{
}

const config::map_channel_configuration& map_channel::configuration() const noexcept
{
	return _configuration;
}

bool map_channel::has_registry() const noexcept
{
	return _registry != nullptr;
}

key_registry& map_channel::registry() noexcept
{
	LTTNG_ASSERT(_registry);
	return *_registry;
}

const key_registry& map_channel::registry() const noexcept
{
	LTTNG_ASSERT(_registry);
	return *_registry;
}

std::weak_ptr<key_registry> map_channel::registry_observer() const noexcept
{
	/* Empty for INDEX-keyed channels, which carry no registry. */
	return _registry;
}

shared_group& map_channel::shared() noexcept
{
	return _shared;
}

const shared_group& map_channel::shared() const noexcept
{
	return _shared;
}

void map_channel::for_each_element_of(const group& target_group,
				      const element_visitor& visitor) const
{
	if (!_registry) {
		LTTNG_THROW_ERROR(lttng::format(
			"Cannot iterate over a map channel's elements without a key registry: map_name=`{}`",
			_configuration.name));
	}

	_registry->for_each(
		[&target_group, &visitor](lttng::c_string_view key, std::uint64_t index) {
			visitor(key, index, target_group.aggregate_element(index));
		});
}

void map_channel::clear()
{
	/*
	 * Reset the channel-wide shared group (which holds the counters
	 * of non-event rule increments and, depending on the dead
	 * process policy, the folded-in counters of defunct processes)
	 * wholesale, then every tracer-backed group of the channel.
	 */
	_shared.clear();
	_clear_tracer_groups();
}

void map_channel::_clear_group_elements(group& target_group)
{
	if (!_registry) {
		/*
		 * Index-keyed channels have no key registry to walk;
		 * their indices are managed by the caller and such
		 * channels are not exposed to lttng_clear_session().
		 */
		return;
	}

	_registry->for_each([&target_group](lttng::c_string_view, std::uint64_t index) {
		target_group.clear_element(index);
	});
}

void map_channel::increment_shared_value(const std::string& key, std::int64_t delta)
{
	if (!_registry) {
		LTTNG_THROW_UNSUPPORTED_ERROR(lttng::format(
			"Cannot resolve a string key on an INDEX-keyed map channel: map_name=`{}`",
			_configuration.name));
	}

	const auto index = _registry->resolve_or_allocate(key);
	_shared.increment(index, delta);
}

std::uint64_t map_channel::allocate_user_token() noexcept
{
	return _next_user_token++;
}

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */
