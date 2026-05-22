/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "map-channel-configuration.hpp"
#include "ust-app.hpp"
#include "ust-map-group.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/scope-exit.hpp>
#include <common/shm.hpp>

#include <lttng/ust-ctl.h>

#include <errno.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace lsc = lttng::sessiond::config;
namespace lsm = lttng::sessiond::map;

namespace {

lttng_ust_ctl_counter_bitness
bitness_from_value_type(lsc::map_channel_configuration::value_type_t type)
{
	switch (type) {
	case lsc::map_channel_configuration::value_type_t::SIGNED_INT_32:
		return LTTNG_UST_CTL_COUNTER_BITNESS_32;
	case lsc::map_channel_configuration::value_type_t::SIGNED_INT_64:
		return LTTNG_UST_CTL_COUNTER_BITNESS_64;
	case lsc::map_channel_configuration::value_type_t::SIGNED_INT_MAX:
		return sizeof(void *) == sizeof(std::uint32_t) ? LTTNG_UST_CTL_COUNTER_BITNESS_32 :
								 LTTNG_UST_CTL_COUNTER_BITNESS_64;
	}

	abort();
}

bool to_tracer_coalesce_hits(lsc::map_channel_configuration::update_policy_t update_policy) noexcept
{
	switch (update_policy) {
	case lsc::map_channel_configuration::update_policy_t::PER_EVENT:
		return true;
	case lsc::map_channel_configuration::update_policy_t::PER_RULE_MATCH:
		return false;
	}

	abort();
}

lsm::element_value from_counter_value(std::int64_t value, bool overflow, bool underflow) noexcept
{
	return lsm::element_value{ value, overflow, underflow };
}

} /* namespace */

namespace lttng {
namespace sessiond {
namespace ust {

void map_group::local_counter_deleter::operator()(
	lttng_ust_ctl_daemon_counter *counter) const noexcept
{
	if (counter) {
		lttng_ust_ctl_destroy_counter(counter);
	}
}

map_group::map_group(const config::map_channel_configuration& configuration,
		     local_counter_uptr local_counter,
		     ust_object_data app_counter_handle) :
	_configuration(configuration),
	_local_counter(std::move(local_counter)),
	_app_counter_handle(std::move(app_counter_handle))
{
}

const config::map_channel_configuration& map_group::configuration() const noexcept
{
	return _configuration;
}

const ust_object_data& map_group::app_counter_handle() const noexcept
{
	return _app_counter_handle;
}

ust_object_data& map_group::app_counter_handle() noexcept
{
	return _app_counter_handle;
}

ust_object_data map_group::_duplicate_app_counter_handle() const
{
	return _app_counter_handle.duplicate();
}

ust_object_data map_group::_duplicate_map_handle(unsigned int cpu) const
{
	/*
	 * The factory inserts one map per CPU in index order, so the
	 * vector position equals the CPU index.
	 */
	LTTNG_ASSERT(cpu < maps().size());
	return maps()[cpu]->handle.duplicate();
}

map_group::app_handle::app_handle(ust::app& app,
				  ust_object_data master_handle,
				  std::vector<ust_object_data> per_cpu_handles) noexcept :
	_app(app),
	_master_handle(std::move(master_handle)),
	_per_cpu_handles(std::move(per_cpu_handles))
{
}

map_group::app_handle::app_handle(app_handle&& other) noexcept :
	_app(other._app),
	_master_handle(std::move(other._master_handle)),
	_per_cpu_handles(std::move(other._per_cpu_handles))
{
	other._moved_from = true;
}

int map_group::app_handle::master_objd() const noexcept
{
	LTTNG_ASSERT(!_moved_from);
	LTTNG_ASSERT(_master_handle.get());
	return _master_handle.get()->header.handle;
}

lttng_ust_abi_object_data *map_group::app_handle::master_object_data() const noexcept
{
	LTTNG_ASSERT(!_moved_from);
	LTTNG_ASSERT(_master_handle.get());
	return _master_handle.get();
}

map_group::app_handle::~app_handle()
{
	if (_moved_from) {
		return;
	}

	/*
	 * Release everything on the application side via its command
	 * socket. Per-CPU handles are released before the master to match
	 * the ordering required by `lttng_ust_ctl_release_object()` (see
	 * `ust-ctl.h`). The local `ust_object_data` envelopes are then
	 * reclaimed by their own destructors.
	 *
	 * Communication errors are only logged: by the time a destructor
	 * runs, the only sensible recovery is local cleanup, and the app
	 * has likely died.
	 */
	try {
		auto guard = _app.command_socket.lock();

		for (auto& cpu_handle : _per_cpu_handles) {
			LTTNG_ASSERT(cpu_handle.get());

			try {
				guard.release_object(cpu_handle.get());
			} catch (const app_communication_error& ex) {
				DBG_FMT("Application unreachable while releasing per-CPU UST counter handle: error=`{}`",
					ex.what());
			} catch (const lttng::runtime_error& ex) {
				DBG_FMT("Failed to release per-CPU UST counter handle: error=`{}`",
					ex.what());
			}
		}

		LTTNG_ASSERT(_master_handle.get());

		try {
			guard.release_object(_master_handle.get());
		} catch (const app_communication_error& ex) {
			DBG_FMT("Application unreachable while releasing master UST counter handle: error=`{}`",
				ex.what());
		} catch (const lttng::runtime_error& ex) {
			DBG_FMT("Failed to release master UST counter handle: error=`{}`",
				ex.what());
		}
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to release UST counter handles via app command socket: error=`{}`",
			ex.what());
	}
}

map_group::app_handle map_group::attach_to_app(ust::app& app, int parent_handle)
{
	/*
	 * Duplicate the master and each per-partition handle locally to
	 * hand them off to the app. Nothing has been shared with the
	 * application yet, so any throw during this phase is cleaned up
	 * by `ust_object_data`'s destructors (i.e. no app-side rollback
	 * needed).
	 */
	auto master = _duplicate_app_counter_handle();

	std::vector<ust_object_data> per_cpu_local;
	per_cpu_local.reserve(map_count());
	for (const auto& m : maps()) {
		per_cpu_local.emplace_back(_duplicate_map_handle(*m->cpu_id));
	}

	/*
	 * Send each duplicate over the command socket. Track how far we
	 * got so the rollback releases only what the application has
	 * actually seen, in reverse order (per-CPU first, master last).
	 */
	bool master_sent = false;
	std::size_t per_cpu_sent_count = 0;
	auto rollback_app_side = lttng::make_scope_exit([&]() noexcept {
		try {
			auto guard = app.command_socket.lock();

			for (std::size_t i = per_cpu_sent_count; i > 0; --i) {
				auto& cpu_handle = per_cpu_local[i - 1];
				LTTNG_ASSERT(cpu_handle.get());

				try {
					guard.release_object(cpu_handle.get());
				} catch (const app_communication_error& ex) {
					DBG_FMT("Application unreachable while rolling back per-CPU UST counter handle: error=`{}`",
						ex.what());
				} catch (const lttng::runtime_error& ex) {
					DBG_FMT("Failed to release per-CPU UST counter handle during rollback: error=`{}`",
						ex.what());
				}
			}

			if (master_sent) {
				LTTNG_ASSERT(master.get());

				try {
					guard.release_object(master.get());
				} catch (const app_communication_error& ex) {
					DBG_FMT("Application unreachable while rolling back master UST counter handle: error=`{}`",
						ex.what());
				} catch (const lttng::runtime_error& ex) {
					DBG_FMT("Failed to release master UST counter handle during rollback: error=`{}`",
						ex.what());
				}
			}
		} catch (const std::exception& ex) {
			ERR_FMT("Failed to release UST counter handles during attach rollback: error=`{}`",
				ex.what());
		}
	});

	{
		auto guard = app.command_socket.lock();

		guard.send_counter_data_to_ust(parent_handle, master.get());
		master_sent = true;
		/*
		 * The counter handles don't need to be held anymore;
		 * drop the sessiond's local copies as each send succeeds.
		 * See `ust_object_data::release_local_fds()` for the
		 * per-type rules.
		 */
		master.release_local_fds();

		for (auto& cpu_data : per_cpu_local) {
			guard.send_counter_cpu_data_to_ust(master.get(), cpu_data.get());
			per_cpu_sent_count++;
			cpu_data.release_local_fds();
		}
	}

	rollback_app_side.disarm();

	return app_handle(app, std::move(master), std::move(per_cpu_local));
}

map::element_value map_group::aggregate_element(std::uint64_t index) const
{
	const std::size_t dimension_indexes[1] = { index };
	std::int64_t value = 0;
	bool overflow = false, underflow = false;

	const auto ret = lttng_ust_ctl_counter_aggregate(
		_local_counter.get(), dimension_indexes, &value, &overflow, &underflow);
	if (ret) {
		if (-ret == EOVERFLOW) {
			LTTNG_THROW_MAP_ELEMENT_INDEX_OUT_OF_RANGE(lttng::format(
				"Map element index out of range: map_name=`{}`, index={}",
				_configuration.name,
				index));
		}

		LTTNG_THROW_POSIX(
			lttng::format("Failed to aggregate UST map element: map_name=`{}`, index={}",
				      _configuration.name,
				      index),
			-ret);
	}

	return from_counter_value(value, overflow, underflow);
}

void map_group::clear_element(std::uint64_t index)
{
	const std::size_t dimension_indexes[1] = { index };

	const auto ret = lttng_ust_ctl_counter_clear(_local_counter.get(), dimension_indexes);
	if (ret) {
		if (-ret == EOVERFLOW) {
			LTTNG_THROW_MAP_ELEMENT_INDEX_OUT_OF_RANGE(lttng::format(
				"Map element index out of range: map_name=`{}`, index={}",
				_configuration.name,
				index));
		}

		LTTNG_THROW_POSIX(
			lttng::format("Failed to clear UST map element: map_name=`{}`, index={}",
				      _configuration.name,
				      index),
			-ret);
	}
}

map_group map_group::create_from_config(const config::map_channel_configuration& configuration)
{
	const auto nr_cpu = static_cast<unsigned int>(lttng_ust_ctl_get_nr_cpu_per_counter());

	/*
	 * Per-CPU shm fds. Ownership is transferred to the local counter
	 * on success; the scope_exit guard closes any fds that were opened
	 * if we throw before that hand-off.
	 */
	std::vector<int> cpu_counter_fds(nr_cpu, -1);
	auto fds_guard = lttng::make_scope_exit([&cpu_counter_fds]() noexcept {
		for (auto fd : cpu_counter_fds) {
			if (fd >= 0) {
				(void) ::close(fd);
			}
		}
	});

	for (unsigned int i = 0; i < nr_cpu; i++) {
		const int fd = shm_create_anonymous("ust-map-counter");
		if (fd < 0) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to create shared memory for UST map group: map_name=`{}`, cpu={}",
				configuration.name,
				i));
		}

		cpu_counter_fds[i] = fd;
	}

	lttng_ust_ctl_counter_dimension dimension = {};
	dimension.size = configuration.max_entry_count;
	/*
	 * These flags don't request value-overflow tracking; that is always
	 * reported through the counter's read and aggregate results. They
	 * instead reserve a catch-all bucket, located at underflow_index or
	 * overflow_index, which absorbs hits whose key can't be allocated a
	 * slot of its own, for example once the dimension is full. The
	 * user space tracer doesn't implement this yet, so leave them off.
	 */
	dimension.has_underflow = false;
	dimension.has_overflow = false;

	auto *local_counter_raw =
		lttng_ust_ctl_create_counter(1,
					     &dimension,
					     0,
					     -1,
					     nr_cpu,
					     cpu_counter_fds.data(),
					     bitness_from_value_type(configuration.value_type),
					     LTTNG_UST_CTL_COUNTER_ARITHMETIC_MODULAR,
					     LTTNG_UST_CTL_COUNTER_ALLOC_PER_CPU,
					     to_tracer_coalesce_hits(configuration.update_policy));
	if (!local_counter_raw) {
		LTTNG_THROW_ERROR(lttng::format("Failed to create UST local counter: map_name=`{}`",
						configuration.name));
	}

	/* Ownership of the per-CPU fds has been transferred to the local counter. */
	fds_guard.disarm();

	local_counter_uptr local_counter(local_counter_raw);

	/*
	 * Build the app-side object handle (`lttng_ust_abi_object_data`)
	 * that the orchestrator will later ship to applications via
	 * lttng_ust_ctl_send_counter_data_to_ust(); after that send,
	 * its `header.handle` refers to the app-side counter.
	 */
	lttng_ust_abi_object_data *app_handle_raw = nullptr;
	if (lttng_ust_ctl_create_counter_data(local_counter.get(), &app_handle_raw) != 0) {
		LTTNG_THROW_ERROR(
			lttng::format("Failed to create UST app counter handle: map_name=`{}`",
				      configuration.name));
	}

	ust_object_data app_counter_handle(app_handle_raw);
	map_group group(configuration, std::move(local_counter), std::move(app_counter_handle));

	for (unsigned int i = 0; i < nr_cpu; i++) {
		lttng_ust_abi_object_data *cpu_obj_raw = nullptr;

		const auto ret = lttng_ust_ctl_create_counter_cpu_data(
			group._local_counter.get(), i, &cpu_obj_raw);
		if (ret) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to create UST per-CPU app counter handle: map_name=`{}`, cpu={}, ret={}",
				configuration.name,
				i,
				ret));
		}

		group.add_map(i, ust_object_data(cpu_obj_raw));
	}

	return group;
}

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
