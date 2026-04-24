/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MODULES_MAP_GROUP_HPP
#define LTTNG_SESSIOND_MODULES_MAP_GROUP_HPP

#include "map-group.hpp"

#include <common/file-descriptor.hpp>

#include <cstdint>

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace modules {

/*
 * The kernel tracer exposes no sessiond-visible per-CPU handle for
 * counters.
 *
 * This type exists only to keep the sessiond::map::group<MapHandleType>
 * template shape symmetric with the UST side.
 */
struct kernel_map_handle {};

/*
 * Runtime representation of a kernel map group managed by the
 * LTTng-modules tracer.
 *
 * Constructed by the modules orchestrator after it has issued
 * LTTNG_KERNEL_ABI_COUNTER on the parent fd (a session fd for map
 * channels; an event-notifier-group fd for error accounting) using the
 * attributes carried by the supplied map_channel_configuration.
 */
class map_group final : public sessiond::map::group<kernel_map_handle> {
public:
	explicit map_group(lttng::file_descriptor tracer_counter_fd,
			   const config::map_channel_configuration& configuration);

	~map_group() override = default;

	map_group(map_group&&) = default;
	map_group(const map_group&) = delete;
	map_group& operator=(map_group&&) = delete;
	map_group& operator=(const map_group&) = delete;

	lttng::file_descriptor& tracer_handle() noexcept;
	const lttng::file_descriptor& tracer_handle() const noexcept;

	const config::map_channel_configuration& configuration() const noexcept;

	sessiond::map::element_value read_element(std::uint64_t index, int cpu) const;
	sessiond::map::element_value aggregate_element(std::uint64_t index) const;
	void clear_element(std::uint64_t index);

	/*
	 * Create a kernel map group whose counter is attached to an
	 * event-notifier group fd. Used by event-notifier error
	 * accounting, which owns one counter per event-notifier group.
	 *
	 * Throws on ioctl or fcntl failure.
	 */
	static map_group
	create_for_event_notifier_group(int event_notifier_group_fd,
					const config::map_channel_configuration& configuration);

	/*
	 * Create a kernel map group whose counter is attached to a
	 * recording-session fd. Placeholder for the map-channel work;
	 * unimplemented for now.
	 */
	static map_group create_for_session(int session_fd,
					    const config::map_channel_configuration& configuration);

private:
	lttng::file_descriptor _tracer_counter_fd;
	const config::map_channel_configuration& _configuration;
};

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MODULES_MAP_GROUP_HPP */
