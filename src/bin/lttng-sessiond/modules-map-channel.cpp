/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "map-channel-configuration.hpp"
#include "modules-map-channel.hpp"

#include <common/macros.hpp>

#include <utility>

namespace lttng {
namespace sessiond {
namespace modules {

map_channel::map_channel(const config::map_channel_configuration& configuration,
			 sessiond::map::key_registry::uptr registry,
			 modules::map_group kernel_group) :
	sessiond::map::map_channel(configuration, std::move(registry)),
	_kernel_group(std::move(kernel_group))
{
	/* The domain gates ownership; a kernel channel only ever sees SYSTEM. */
	LTTNG_ASSERT(configuration.buffer_ownership == config::ownership_model_t::SYSTEM);
}

modules::map_group& map_channel::kernel_group() noexcept
{
	return _kernel_group;
}

const modules::map_group& map_channel::kernel_group() const noexcept
{
	return _kernel_group;
}

void map_channel::for_each_group(const group_visitor& visitor) const
{
	/*
	 * A kernel map channel has a single system-wide group and, following
	 * the public model, exposes no shared group.
	 */
	visitor(sessiond::map::group_description{ sessiond::map::group_identity{
							  sessiond::map::group_type::KERNEL_GLOBAL,
							  nonstd::nullopt,
							  _kernel_group.value_type() },
						  nonstd::nullopt },
		_kernel_group);
}

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */
