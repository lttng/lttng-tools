/*
 * SPDX-FileCopyrightText: 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "stream-descriptor.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/readwrite.hpp>

#include <cstddef>
#include <limits>
#include <unistd.h>

namespace lttng {

void input_stream_descriptor::read(void *buffer, std::size_t size)
{
	const auto read_ret = read_some(buffer, size);
	if (static_cast<std::size_t>(read_ret) != size) {
		LTTNG_THROW_POSIX(
			lttng::format(
				"Failed to read enough data from file descriptor: fd={}, requested_size={}, amount_read={}",
				fd(),
				size,
				read_ret),
			errno);
	}
}

std::size_t input_stream_descriptor::read_some(void *buffer, std::size_t max_size)
{
	using lttng_read_return_type = decltype(lttng_read(
		std::declval<int>(), std::declval<void *>(), std::declval<size_t>()));
	constexpr auto max_supported_read_size = std::numeric_limits<lttng_read_return_type>::max();

	if (max_size > max_supported_read_size) {
		LTTNG_THROW_UNSUPPORTED_ERROR(lttng::format(
			"Read size exceeds the maximal supported value of lttng_read: read_size={}, maximal_read_size={}",
			max_size,
			max_supported_read_size));
	}

	const auto read_ret = lttng_read(fd(), buffer, max_size);
	if (read_ret < 0) {
		LTTNG_THROW_POSIX(lttng::format("Failed to read from file descriptor: fd={}", fd()),
				  errno);
	}

	return read_ret;
}

void output_stream_descriptor::write(const void *buffer, std::size_t size)
{
	using lttng_write_return_type = decltype(lttng_write(
		std::declval<int>(), std::declval<const void *>(), std::declval<size_t>()));
	constexpr auto max_supported_write_size =
		std::numeric_limits<lttng_write_return_type>::max();

	if (size > max_supported_write_size) {
		LTTNG_THROW_UNSUPPORTED_ERROR(lttng::format(
			"Write size exceeds the maximal supported value of lttng_write: write_size={}, maximal_write_size={}",
			size,
			max_supported_write_size));
	}

	const auto write_ret = lttng_write(fd(), buffer, size);
	if (write_ret < 0 || static_cast<std::size_t>(write_ret) != size) {
		LTTNG_THROW_POSIX(lttng::format("Failed to write to file descriptor: fd={}", fd()),
				  errno);
	}
}

} /* namespace lttng */
