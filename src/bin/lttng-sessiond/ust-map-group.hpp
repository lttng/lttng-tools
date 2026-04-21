/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_MAP_GROUP_HPP
#define LTTNG_SESSIOND_UST_MAP_GROUP_HPP

#include "map-group.hpp"
#include "ust-object-data.hpp"

#include <lttng/ust-ctl.h>

#include <cstdint>
#include <memory>

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace ust {

/*
 * Runtime representation of a UST map group: the daemon counter and
 * its per-CPU counter_cpu handles backing one map_channel_configuration
 * for a given uid+abi (per-UID mode) or app (per-PID mode).
 *
 * Constructed by the UST orchestrator after it has created the
 * per-CPU shm FDs, the `lttng_ust_ctl_daemon_counter`, and the
 * master counter object from the fields of the supplied
 * (map_channel_configuration.
 *
 * In per-UID mode, the first application with a matching (uid, abi)
 * drives the creation; subsequent applications receive duplicates of
 * the master counter object and of each per-CPU map handle.
 */
class map_group final : public sessiond::map::group<ust_object_data> {
public:
	struct daemon_counter_deleter {
		void operator()(lttng_ust_ctl_daemon_counter *) const noexcept;
	};

	using daemon_counter_uptr =
		std::unique_ptr<lttng_ust_ctl_daemon_counter, daemon_counter_deleter>;

	explicit map_group(const config::map_channel_configuration& configuration,
			   daemon_counter_uptr daemon_counter,
			   ust_object_data counter_object);

	~map_group() override = default;

	map_group(map_group&&) = delete;
	map_group(const map_group&) = delete;
	map_group& operator=(map_group&&) = delete;
	map_group& operator=(const map_group&) = delete;

	const config::map_channel_configuration& configuration() const noexcept;

	const ust_object_data& counter_object() const noexcept;
	ust_object_data& counter_object() noexcept;

	/*
	 * Duplicate the "group" counter object for sending to a
	 * newly-registered application.
	 */
	ust_object_data duplicate_counter_object() const;

	/*
	 * Duplicate the per-CPU counter_cpu handle at `cpu` to send it
	 * to a newly-registered application.
	 */
	ust_object_data duplicate_map_handle(unsigned int cpu) const;

	sessiond::map::element_value read_element(std::uint64_t index, int cpu) const;
	sessiond::map::element_value aggregate_element(std::uint64_t index) const;
	void clear_element(std::uint64_t index);

private:
	const config::map_channel_configuration& _configuration;
	daemon_counter_uptr _daemon_counter;
	ust_object_data _counter_object;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_MAP_GROUP_HPP */
