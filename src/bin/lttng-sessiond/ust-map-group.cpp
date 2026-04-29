/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "map-channel-configuration.hpp"
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

ust_object_data map_group::duplicate_app_counter_handle() const
{
	return _app_counter_handle.duplicate();
}

ust_object_data map_group::duplicate_map_handle(unsigned int cpu) const
{
	/*
	 * The factory inserts one map per CPU in index order, so the
	 * vector position equals the CPU index.
	 */
	LTTNG_ASSERT(cpu < maps().size());
	return maps()[cpu]->handle.duplicate();
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
