/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "map-channel-configuration.hpp"
#include "modules-map-group.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/lttng-kernel.hpp>
#include <common/make-unique.hpp>
#include <common/scope-exit.hpp>

#include <cstdint>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <utility>

namespace {

/*
 * Build a single-dimension counter index referencing `index_storage`. The
 * counter ABI reads the dimension indexes through a pointer
 * (lttng_kernel_abi_counter_index::ptr), so the storage must outlive both the
 * returned index and the ioctl that consumes it; the caller owns it.
 */
lttng_kernel_abi_counter_index single_dimension_index(const std::uint64_t& index_storage) noexcept
{
	lttng_kernel_abi_counter_index counter_index{};

	counter_index.number_dimensions = 1;
	counter_index.ptr = reinterpret_cast<std::uint64_t>(&index_storage);
	return counter_index;
}

lttng::sessiond::map::element_value
from_counter_value(const lttng_kernel_abi_counter_value& value) noexcept
{
	return lttng::sessiond::map::element_value{
		value.value,
		(value.flags & LTTNG_KERNEL_ABI_COUNTER_VALUE_FLAG_OVERFLOW) != 0,
		(value.flags & LTTNG_KERNEL_ABI_COUNTER_VALUE_FLAG_UNDERFLOW) != 0
	};
}

lttng_kernel_abi_counter_bitness bitness_from_value_type(
	lttng::sessiond::config::map_channel_configuration::value_type_t vt) noexcept
{
	using value_type_t = lttng::sessiond::config::map_channel_configuration::value_type_t;

	switch (vt) {
	case value_type_t::SIGNED_INT_32:
		return LTTNG_KERNEL_ABI_COUNTER_BITNESS_32;
	case value_type_t::SIGNED_INT_64:
		return LTTNG_KERNEL_ABI_COUNTER_BITNESS_64;
	case value_type_t::SIGNED_INT_MAX:
		/*
		 * Widest bitness the running kernel supports. We guess the
		 * kernel's ABI by checking the session daemon's own ABI which
		 * is not strictly correct.
		 */
		return sizeof(void *) == sizeof(std::uint32_t) ?
			LTTNG_KERNEL_ABI_COUNTER_BITNESS_32 :
			LTTNG_KERNEL_ABI_COUNTER_BITNESS_64;
	}

	abort();
}

std::uint32_t conf_flags_from_update_policy(
	lttng::sessiond::config::map_channel_configuration::update_policy_t update_policy) noexcept
{
	using update_policy_t = lttng::sessiond::config::map_channel_configuration::update_policy_t;

	switch (update_policy) {
	case update_policy_t::PER_EVENT:
		return LTTNG_KERNEL_ABI_COUNTER_CONF_FLAG_COALESCE_HITS;
	case update_policy_t::PER_RULE_MATCH:
		return 0;
	}

	abort();
}

/*
 * Build the counter configuration for `configuration`. The single counter
 * dimension is returned through `dimension`: the counter ABI references the
 * dimension array by pointer (dimension_array.ptr), so its storage must
 * outlive the returned conf and the ioctl that consumes it; the caller owns it.
 */
lttng_kernel_abi_counter_conf
make_counter_conf(const lttng::sessiond::config::map_channel_configuration& configuration,
		  lttng_kernel_abi_counter_dimension& dimension) noexcept
{
	dimension = {};
	dimension.size = configuration.max_entry_count;

	lttng_kernel_abi_counter_conf conf{};

	conf.len = sizeof(conf);
	conf.flags = conf_flags_from_update_policy(configuration.update_policy);
	conf.arithmetic = LTTNG_KERNEL_ABI_COUNTER_ARITHMETIC_MODULAR;
	conf.bitness = bitness_from_value_type(configuration.value_type);
	conf.global_sum_step = 0;
	conf.dimension_array.number_dimensions = 1;
	conf.dimension_array.elem_len = sizeof(dimension);
	conf.dimension_array.ptr = reinterpret_cast<std::uint64_t>(&dimension);
	return conf;
}

} /* namespace */

namespace lttng {
namespace sessiond {
namespace modules {

map_group::map_group(lttng::file_descriptor tracer_counter_fd,
		     const config::map_channel_configuration& configuration) :
	_tracer_counter_fd(
		lttng::make_unique<lttng::file_descriptor>(std::move(tracer_counter_fd))),
	_configuration(configuration)
{
}

lttng::file_descriptor& map_group::tracer_handle() noexcept
{
	return *_tracer_counter_fd;
}

const lttng::file_descriptor& map_group::tracer_handle() const noexcept
{
	return *_tracer_counter_fd;
}

const config::map_channel_configuration& map_group::configuration() const noexcept
{
	return _configuration;
}

map::element_value map_group::read_element(std::uint64_t index, int cpu) const
{
	const std::uint64_t dimension_index = index;
	lttng_kernel_abi_counter_read counter_read{};

	counter_read.len = sizeof(counter_read);
	counter_read.index = single_dimension_index(dimension_index);
	counter_read.cpu = cpu;

	const auto ret = kernctl_counter_read(_tracer_counter_fd->fd(), &counter_read);
	if (ret != 0) {
		switch (-ret) {
		case EOVERFLOW:
			LTTNG_THROW_MAP_ELEMENT_INDEX_OUT_OF_RANGE(lttng::format(
				"Map element index out of range: map_name=`{}`, index={}, cpu={}",
				_configuration.name,
				index,
				cpu));
		case EINVAL:
			/*
			 * EINVAL is used for both unsuitable cpu argument
			 * (mismatched allocation mode or out of num_possible_cpus())
			 * and for sessiond-side programming errors (struct sizing,
			 * number_dimensions).
			 *
			 * Given that the input struct is constructed locally and
			 * known-correct, surface this as an invalid-cpu error to
			 * the caller.
			 */
			LTTNG_THROW_MAP_ELEMENT_INVALID_CPU(lttng::format(
				"Invalid cpu for kernel map element read: map_name=`{}`, index={}, cpu={}",
				_configuration.name,
				index,
				cpu));
		default:
			LTTNG_THROW_POSIX(
				lttng::format(
					"Failed to read kernel map element: map_name=`{}`, index={}, cpu={}",
					_configuration.name,
					index,
					cpu),
				-ret);
		}
	}

	return from_counter_value(counter_read.value);
}

map::element_value map_group::aggregate_element(std::uint64_t index) const
{
	const std::uint64_t dimension_index = index;
	lttng_kernel_abi_counter_aggregate counter_aggregate{};

	counter_aggregate.len = sizeof(counter_aggregate);
	counter_aggregate.index = single_dimension_index(dimension_index);

	const auto ret =
		kernctl_counter_get_aggregate_value(_tracer_counter_fd->fd(), &counter_aggregate);
	if (ret != 0) {
		if (-ret == EOVERFLOW) {
			LTTNG_THROW_MAP_ELEMENT_INDEX_OUT_OF_RANGE(lttng::format(
				"Map element index out of range: map_name=`{}`, index={}",
				_configuration.name,
				index));
		}

		LTTNG_THROW_POSIX(
			lttng::format(
				"Failed to aggregate kernel map element: map_name=`{}`, index={}",
				_configuration.name,
				index),
			-ret);
	}

	return from_counter_value(counter_aggregate.value);
}

void map_group::clear_element(std::uint64_t index)
{
	const std::uint64_t dimension_index = index;
	lttng_kernel_abi_counter_clear counter_clear{};

	counter_clear.len = sizeof(counter_clear);
	counter_clear.index = single_dimension_index(dimension_index);

	const auto ret = kernctl_counter_clear(_tracer_counter_fd->fd(), &counter_clear);
	if (ret != 0) {
		if (-ret == EOVERFLOW) {
			LTTNG_THROW_MAP_ELEMENT_INDEX_OUT_OF_RANGE(lttng::format(
				"Map element index out of range: map_name=`{}`, index={}",
				_configuration.name,
				index));
		}

		LTTNG_THROW_POSIX(
			lttng::format("Failed to clear kernel map element: map_name=`{}`, index={}",
				      _configuration.name,
				      index),
			-ret);
	}
}

map_group
map_group::create_for_event_notifier_group(int event_notifier_group_fd,
					   const config::map_channel_configuration& configuration)
{
	lttng_kernel_abi_counter_dimension dimension;
	const auto conf = make_counter_conf(configuration, dimension);

	const auto raw_fd =
		kernctl_create_event_notifier_group_error_counter(event_notifier_group_fd, &conf);
	if (raw_fd < 0) {
		LTTNG_THROW_POSIX(
			lttng::format(
				"Failed to create event notifier group error counter: map_name=`{}`, event_notifier_group_fd={}",
				configuration.name,
				event_notifier_group_fd),
			-raw_fd);
	}

	auto fd_guard = lttng::make_scope_exit([raw_fd]() noexcept { (void) ::close(raw_fd); });

	/* Prevent fd duplication after execlp(). */
	if (::fcntl(raw_fd, F_SETFD, FD_CLOEXEC) < 0) {
		const auto errno_copy = errno;

		LTTNG_THROW_POSIX(
			lttng::format(
				"Failed to set FD_CLOEXEC on kernel map group counter fd: map_name=`{}`, fd={}",
				configuration.name,
				raw_fd),
			errno_copy);
	}

	fd_guard.disarm();

	return map_group(lttng::file_descriptor(raw_fd), configuration);
}

map_group map_group::create_for_session(int session_fd,
					const config::map_channel_configuration& configuration)
{
	lttng_kernel_abi_counter_dimension dimension;
	const auto conf = make_counter_conf(configuration, dimension);

	const auto raw_fd = kernctl_create_session_counter(session_fd, &conf);
	if (raw_fd < 0) {
		LTTNG_THROW_POSIX(
			lttng::format(
				"Failed to create session counter: map_name=`{}`, session_fd={}",
				configuration.name,
				session_fd),
			-raw_fd);
	}

	auto fd_guard = lttng::make_scope_exit([raw_fd]() noexcept { (void) ::close(raw_fd); });

	/* Prevent fd duplication after execlp(). */
	if (::fcntl(raw_fd, F_SETFD, FD_CLOEXEC) < 0) {
		const auto errno_copy = errno;

		LTTNG_THROW_POSIX(
			lttng::format(
				"Failed to set FD_CLOEXEC on kernel map group counter fd: map_name=`{}`, fd={}",
				configuration.name,
				raw_fd),
			errno_copy);
	}

	fd_guard.disarm();

	return map_group(lttng::file_descriptor(raw_fd), configuration);
}

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */
