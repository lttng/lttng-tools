/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "file-descriptor.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/readwrite.hpp>

#include <algorithm>
#include <limits>
#include <unistd.h>

namespace {
bool is_valid_fd(int fd)
{
	return fd >= 0;
}
} // anonymous namespace

lttng::file_descriptor::file_descriptor(int raw_fd) noexcept : _raw_fd{ raw_fd }
{
	LTTNG_ASSERT(is_valid_fd(_raw_fd));
}

lttng::file_descriptor::file_descriptor(lttng::file_descriptor&& other) noexcept
{
	std::swap(_raw_fd, other._raw_fd);
}

lttng::file_descriptor& lttng::file_descriptor::operator=(lttng::file_descriptor&& other) noexcept
{
	_cleanup();
	std::swap(_raw_fd, other._raw_fd);
	return *this;
}

lttng::file_descriptor::~file_descriptor() noexcept
{
	_cleanup();
}

int lttng::file_descriptor::fd() const noexcept
{
	LTTNG_ASSERT(is_valid_fd(_raw_fd));
	return _raw_fd;
}

void lttng::file_descriptor::_cleanup() noexcept
{
	if (!is_valid_fd(_raw_fd)) {
		return;
	}

	const auto ret = ::close(_raw_fd);

	_raw_fd = -1;
	if (ret) {
		PERROR("Failed to close file descriptor: fd=%i", _raw_fd);
	}
}

void lttng::file_descriptor::write(const void *buffer, std::size_t size)
{
	/*
	 * This is a limitation of the internal helper that is not a problem in practice for the
	 * moment.
	 */
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

void lttng::file_descriptor::read(void *buffer, std::size_t size)
{
	/*
	 * This is a limitation of the internal helper that is not a problem in practice for the
	 * moment.
	 */
	using lttng_read_return_type = decltype(lttng_read(
		std::declval<int>(), std::declval<void *>(), std::declval<size_t>()));
	constexpr auto max_supported_read_size = std::numeric_limits<lttng_read_return_type>::max();

	if (size > max_supported_read_size) {
		LTTNG_THROW_UNSUPPORTED_ERROR(lttng::format(
			"Read size exceeds the maximal supported value of lttng_read: read_size={}, maximal_read_size={}",
			size,
			max_supported_read_size));
	}

	const auto read_ret = lttng_read(fd(), buffer, size);
	if (read_ret < 0 || static_cast<std::size_t>(read_ret) != size) {
		LTTNG_THROW_POSIX(lttng::format("Failed to read from file descriptor: fd={}", fd()),
				  errno);
	}
}
