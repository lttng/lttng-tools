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
 * file descriptor.
 */
class file_descriptor {
public:
	file_descriptor()
	{
	}

	explicit file_descriptor(int raw_fd) noexcept : _raw_fd{ raw_fd }
	{
		LTTNG_ASSERT(_is_valid_fd(_raw_fd));
	}

	file_descriptor(const file_descriptor&) = delete;
	file_descriptor& operator=(const file_descriptor&) = delete;
	file_descriptor& operator=(file_descriptor&& other)
	{
		_cleanup();
		std::swap(_raw_fd, other._raw_fd);
		return *this;
	}

	file_descriptor(file_descriptor&& other) noexcept
	{
		std::swap(_raw_fd, other._raw_fd);
	}

	~file_descriptor()
	{
		_cleanup();
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

	void _cleanup()
	{
		if (!_is_valid_fd(_raw_fd)) {
			return;
		}

		const auto ret = ::close(_raw_fd);

		_raw_fd = -1;
		if (ret) {
			PERROR("Failed to close file descriptor: fd=%i", _raw_fd);
		}
	}

	int _raw_fd = -1;
};

} /* namespace lttng */
