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
 * Runtime representation of a UST map group backing one
 * map_channel_configuration for a given uid+abi (per-UID mode) or app
 * (per-PID mode).
 */
class map_group final : public sessiond::map::group<ust_object_data> {
public:
	struct local_counter_deleter {
		void operator()(lttng_ust_ctl_daemon_counter *) const noexcept;
	};

	using local_counter_uptr =
		std::unique_ptr<lttng_ust_ctl_daemon_counter, local_counter_deleter>;

	explicit map_group(const config::map_channel_configuration& configuration,
			   local_counter_uptr local_counter,
			   ust_object_data app_counter_handle);

	~map_group() override = default;

	map_group(map_group&&) = default;
	map_group(const map_group&) = delete;
	map_group& operator=(map_group&&) = delete;
	map_group& operator=(const map_group&) = delete;

	/*
	 * Create a fully-wired UST map group from a map channel
	 * configuration. Allocates the per-CPU shm fds, creates the
	 * sessiond's local counter, and builds the master + per-CPU
	 * app handles used to share the counter with applications.
	 *
	 * Throws on allocation or ustctl failure.
	 */
	static map_group create_from_config(const config::map_channel_configuration& configuration);

	const config::map_channel_configuration& configuration() const noexcept;

	const ust_object_data& app_counter_handle() const noexcept;
	ust_object_data& app_counter_handle() noexcept;

	/*
	 * Duplicate the "group" app counter handle for sending to a
	 * newly-registered application.
	 */
	ust_object_data duplicate_app_counter_handle() const;

	/*
	 * Duplicate the per-CPU app counter handle at `cpu` to send it
	 * to a newly-registered application.
	 */
	ust_object_data duplicate_map_handle(unsigned int cpu) const;

	sessiond::map::element_value aggregate_element(std::uint64_t index) const;
	void clear_element(std::uint64_t index);

private:
	const config::map_channel_configuration& _configuration;

	/*
	 * A UST counter (map group) has two distinct sessiond-side references:
	 *
	 *   - the local counter (`_local_counter`): the sessiond's own
	 *     in-process counter state, returned by
	 *     `lttng_ust_ctl_create_counter()`. It owns the per-CPU shm
	 *     mappings in the sessiond's address space and is the parameter
	 *     passed to `lttng_ust_ctl_counter_{read,aggregate,clear}()` —
	 *     those operations execute locally against the mmap and never
	 *     talk to the application.
	 *
	 *   - the app counter handle (`_app_counter_handle`): a wire-format
	 *     envelope (`lttng_ust_abi_object_data`) describing the same
	 *     logical counter, built by `lttng_ust_ctl_create_counter_data()`.
	 *
	 *     After being shipped over the app socket via
	 *     `lttng_ust_ctl_send_counter_data_to_ust()`, its `header.handle`
	 *     is filled with the integer handle that the app uses to refer to
	 *     its own copy of the counter. This is the parameter passed to
	 *     app-targeted operations (e.g. attaching event rules).
	 *
	 * The two references describe the same logical counter from each
	 * side: the sessiond can read it locally because it mapped the shm,
	 * and the application increments it locally because it mapped the
	 * same shm. The app handle just lets the sessiond ask an app to install
	 * rules against it.
	 *
	 * The same split applies to each per-CPU sub-counter: the per-CPU
	 * shm mapping lives inside `_local_counter`, while the per-CPU
	 * app handles are stored in the base group's `maps()` collection.
	 */
	local_counter_uptr _local_counter;
	ust_object_data _app_counter_handle;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_MAP_GROUP_HPP */
