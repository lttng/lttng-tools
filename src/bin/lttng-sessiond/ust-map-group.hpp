/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_MAP_GROUP_HPP
#define LTTNG_SESSIOND_UST_MAP_GROUP_HPP

#include "map-channel-configuration.hpp"
#include "map-group.hpp"
#include "ust-application-abi.hpp"
#include "ust-object-data.hpp"

#include <vendor/optional.hpp>

#include <cstdint>
#include <memory>
#include <vector>

struct lttng_ust_ctl_daemon_counter;
struct lttng_ust_abi_object_data;

namespace lttng {
namespace sessiond {

namespace ust {

struct app;

/*
 * Resolve the concrete value type of the counter to hand to an
 * application of `app_abi`, honouring the channel's value type and the
 * running session daemon's own ABI as a ceiling. The result is never
 * SIGNED_INT_MAX:
 *
 * • SIGNED_INT_32: always SIGNED_INT_32 (fits every application).
 *
 * • SIGNED_INT_64: SIGNED_INT_64, but only when both the application and
 *   the session daemon are 64-bit; nullopt otherwise (can't be served).
 *
 * • SIGNED_INT_MAX: SIGNED_INT_64 when both the application and the
 *   session daemon are 64-bit, SIGNED_INT_32 otherwise.
 */
nonstd::optional<config::map_channel_configuration::value_type_t>
resolve_map_value_type(config::map_channel_configuration::value_type_t value_type,
		       application_abi app_abi) noexcept;

/*
 * Runtime representation of a UST map group backing one
 * map_channel_configuration for a given uid+abi (per-UID mode) or app
 * (per-PID mode).
 */
class map_group final : public sessiond::map::group {
public:
	/*
	 * RAII handle representing one application's attachment to this
	 * map group. Holds the duplicated master + per-CPU
	 * `ust_object_data` handles that were sent to the application.
	 *
	 * Constructed exclusively by `map_group::attach_to_app()`.
	 */
	class app_handle final {
	public:
		app_handle(app_handle&& other) noexcept;
		app_handle(const app_handle&) = delete;
		app_handle& operator=(const app_handle&) = delete;
		app_handle& operator=(app_handle&&) = delete;
		~app_handle();

		/*
		 * App-side handle of the master counter. Used to register
		 * the channel with the application's objd_registry so the
		 * notification thread can resolve a map_objd reported by
		 * the app to the channel that owns it.
		 */
		int master_objd() const noexcept;

		/*
		 * App-side object data of the master counter. This is the
		 * `counter_data` argument when installing a counter-event rule
		 * against this application's copy of the counter
		 * (lttng_ust_ctl_counter_create_event). Borrowed; owned by this
		 * handle.
		 */
		lttng_ust_abi_object_data *master_object_data() const noexcept;

	private:
		friend class map_group;

		app_handle(ust::app& app,
			   ust_object_data master_handle,
			   std::vector<ust_object_data> per_cpu_handles) noexcept;

		ust::app& _app;
		bool _moved_from = false;
		ust_object_data _master_handle;
		std::vector<ust_object_data> _per_cpu_handles;
	};

	struct local_counter_deleter {
		void operator()(lttng_ust_ctl_daemon_counter *) const noexcept;
	};

	using local_counter_uptr =
		std::unique_ptr<lttng_ust_ctl_daemon_counter, local_counter_deleter>;

	explicit map_group(const config::map_channel_configuration& configuration,
			   config::map_channel_configuration::value_type_t resolved_value_type,
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
	 * The counter is created with `resolved_value_type`, the concrete
	 * value type resolved for this group's applications (see
	 * `resolve_map_value_type()`); it may be narrower than the channel's
	 * own value type and must never be SIGNED_INT_MAX.
	 *
	 * Throws on allocation or ustctl failure.
	 */
	static map_group
	create_from_config(const config::map_channel_configuration& configuration,
			   config::map_channel_configuration::value_type_t resolved_value_type);

	const config::map_channel_configuration& configuration() const noexcept;

	const ust_object_data& app_counter_handle() const noexcept;
	ust_object_data& app_counter_handle() noexcept;

	/*
	 * Duplicate the master + per-CPU app handles, send them to the
	 * application using `parent_handle` as the app-side parent (the
	 * event-notifier-group handle for event notifier error accounting, the
	 * session handle for a regular map channel) and return an RAII
	 * `app_handle` that releases everything on destruction.
	 *
	 * On a partial failure mid-send the master and any per-CPU
	 * handles already shared with the application are released so the
	 * app sees no residual state.
	 *
	 * Throws on local allocation failure or on app-side communication
	 * failure (`app_communication_error`); the caller is responsible
	 * for translating the latter into a domain-specific status.
	 */
	app_handle attach_to_app(ust::app& app, int parent_handle);

	sessiond::map::element_value read_element(std::uint64_t index, int cpu) const;
	sessiond::map::element_value aggregate_element(std::uint64_t index) const override;
	void for_each_partition(const std::function<void(const sessiond::map::partition_id&)>&
					visitor) const override;
	sessiond::map::element_value
	read_element(std::uint64_t index,
		     const sessiond::map::partition_id& partition) const override;
	void clear_element(std::uint64_t index) override;

private:
	/*
	 * Duplicate the "group" app counter handle for sending to a
	 * newly-registered application.
	 */
	ust_object_data _duplicate_app_counter_handle() const;

	/*
	 * Duplicate the per-CPU app counter handle at `cpu` to send it
	 * to a newly-registered application.
	 */
	ust_object_data _duplicate_map_handle(unsigned int cpu) const;

	const config::map_channel_configuration& _configuration;

	/*
	 * A UST counter (map group) has two distinct sessiond-side references:
	 *
	 *   - the local counter (`_local_counter`): the sessiond's own
	 *     in-process counter state, returned by
	 *     `lttng_ust_ctl_create_counter()`. It owns the per-CPU shm
	 *     mappings in the sessiond's address space and is the parameter
	 *     passed to `lttng_ust_ctl_counter_{read,aggregate,clear}()`.
	 *     Those operations execute locally against the mmap and never
	 *     interact with the application(s).
	 *
	 *   - the app counter handle (`_app_counter_handle`): a communication
	 *     handle (`lttng_ust_abi_object_data`) describing the same
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
	 * app handles are stored in `_per_cpu_app_handles`.
	 */
	local_counter_uptr _local_counter;
	ust_object_data _app_counter_handle;

	/*
	 * One app communication handle per per-CPU sub-counter; the vector
	 * position is the CPU id. Populated in CPU order by
	 * create_from_config().
	 */
	std::vector<ust_object_data> _per_cpu_app_handles;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_MAP_GROUP_HPP */
