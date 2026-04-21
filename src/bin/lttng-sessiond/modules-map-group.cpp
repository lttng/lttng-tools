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

#include <errno.h>
#include <utility>

namespace {

lttng_kernel_abi_counter_index make_single_dimension_index(std::uint64_t index) noexcept
{
	lttng_kernel_abi_counter_index counter_index{};

	counter_index.number_dimensions = 1;
	counter_index.dimension_indexes[0] = index;
	return counter_index;
}

lttng::sessiond::map::element_value
from_counter_value(const lttng_kernel_abi_counter_value& value) noexcept
{
	return lttng::sessiond::map::element_value{ value.value,
						    value.overflow != 0,
						    value.underflow != 0 };
}

} /* namespace */

namespace lttng {
namespace sessiond {
namespace modules {

map_group::map_group(lttng::file_descriptor tracer_counter_fd,
		     const config::map_channel_configuration& configuration) :
	_tracer_counter_fd(std::move(tracer_counter_fd)), _configuration(configuration)
{
}

lttng::file_descriptor& map_group::tracer_handle() noexcept
{
	return _tracer_counter_fd;
}

const lttng::file_descriptor& map_group::tracer_handle() const noexcept
{
	return _tracer_counter_fd;
}

const config::map_channel_configuration& map_group::configuration() const noexcept
{
	return _configuration;
}

map::element_value map_group::read_element(std::uint64_t index, int cpu) const
{
	lttng_kernel_abi_counter_read counter_read{};

	counter_read.index = make_single_dimension_index(index);
	counter_read.cpu = cpu;

	const auto ret = kernctl_counter_read(_tracer_counter_fd.fd(), &counter_read);
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
	lttng_kernel_abi_counter_aggregate counter_aggregate{};

	counter_aggregate.index = make_single_dimension_index(index);

	const auto ret =
		kernctl_counter_get_aggregate_value(_tracer_counter_fd.fd(), &counter_aggregate);
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
	lttng_kernel_abi_counter_clear counter_clear{};

	counter_clear.index = make_single_dimension_index(index);

	const auto ret = kernctl_counter_clear(_tracer_counter_fd.fd(), &counter_clear);
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

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */
