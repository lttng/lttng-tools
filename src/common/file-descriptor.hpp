/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/format.hpp>

#include <algorithm>

#include <unistd.h>

namespace lttng {

/*
 * RAII wrapper around a UNIX file descriptor. A file_descriptor's underlying
 * file descriptor
 */
class file_descriptor {
public:
	explicit file_descriptor(int raw_fd) noexcept : _raw_fd{raw_fd}
	{
		LTTNG_ASSERT(_is_valid_fd(_raw_fd));
	}

	file_descriptor(const file_descriptor&) = delete;

	file_descriptor(file_descriptor&& other) : _raw_fd{-1}
	{
		LTTNG_ASSERT(_is_valid_fd(_raw_fd));
		std::swap(_raw_fd, other._raw_fd);
	}

	~file_descriptor()
	{
		if (!_is_valid_fd(_raw_fd)) {
			return;
		}

		const auto ret = ::close(_raw_fd);
		if (ret) {
			PERROR("Failed to close file descriptor: fd=%i", _raw_fd);
		}
	}

	int fd() const noexcept
	{
		LTTNG_ASSERT(_is_valid_fd(_raw_fd));
		return _raw_fd;
	}

private:
	static bool _is_valid_fd(int fd)
	{
		return fd >= 0;
	}

	int _raw_fd;
};

} /* namespace lttng */
