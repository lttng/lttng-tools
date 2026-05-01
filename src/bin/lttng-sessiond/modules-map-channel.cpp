/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "modules-map-channel.hpp"

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
}

modules::map_group& map_channel::kernel_group() noexcept
{
	return _kernel_group;
}

const modules::map_group& map_channel::kernel_group() const noexcept
{
	return _kernel_group;
}

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */
