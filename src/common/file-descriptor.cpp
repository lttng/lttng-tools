/*
 * SPDX-FileCopyrightText: 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "file-descriptor.hpp"
#include "stream-descriptor.hpp"

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
} /* anonymous namespace */

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
	if (this != &other) {
		_cleanup();
		std::swap(_raw_fd, other._raw_fd);
	}

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

int lttng::file_descriptor::release() noexcept
{
	const auto temp_fd = _raw_fd;

	_raw_fd = -1;
	return temp_fd;
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
