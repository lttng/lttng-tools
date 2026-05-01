/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MODULES_MAP_CHANNEL_HPP
#define LTTNG_SESSIOND_MODULES_MAP_CHANNEL_HPP

#include "key-registry.hpp"
#include "map-channel.hpp"
#include "modules-map-group.hpp"

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace modules {

/*
 * Kernel-domain map channel. Owns exactly one `modules::map_group`
 * (one tracer-side counter per recording session) sitting alongside
 * the base `map_channel`'s shared group and registry.
 */
class map_channel final : public sessiond::map::map_channel {
public:
	map_channel(const config::map_channel_configuration& configuration,
		    sessiond::map::key_registry::uptr registry,
		    modules::map_group kernel_group);

	~map_channel() override = default;
	map_channel(const map_channel&) = delete;
	map_channel(map_channel&&) = delete;
	map_channel& operator=(const map_channel&) = delete;
	map_channel& operator=(map_channel&&) = delete;

	modules::map_group& kernel_group() noexcept;
	const modules::map_group& kernel_group() const noexcept;

private:
	modules::map_group _kernel_group;
};

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MODULES_MAP_CHANNEL_HPP */
