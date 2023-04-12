/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_FILE_DESCRIPTOR_HPP
#define LTTNG_FILE_DESCRIPTOR_HPP

#include <cstddef>

namespace lttng {

/* RAII wrapper around a UNIX file descriptor. */
class file_descriptor {
public:
	file_descriptor() noexcept;

	explicit file_descriptor(int raw_fd) noexcept;
	file_descriptor(const file_descriptor&) = delete;
	file_descriptor& operator=(const file_descriptor&) = delete;

	file_descriptor(file_descriptor&& other) noexcept;

	file_descriptor& operator=(file_descriptor&& other) noexcept;

	~file_descriptor() noexcept;

	/*
	 * Read `size` bytes from the underlying file descriptor, assuming
	 * raw_fd behaves as a blocking device.
	 *
	 * Throws an exception if the requested amount of bytes couldn't be read.
	 */
	void read(void *buffer, std::size_t size);
	/*
	 * Write `size` bytes to the underlying file descriptor, assuming
	 * raw_fd behaves as a blocking device.
	 *
	 * Throws an exception if the requested amount of bytes couldn't be written.
	 */
	void write(const void *buffer, std::size_t size);

	int fd() const noexcept;

protected:
	void _cleanup() noexcept;

private:
	int _raw_fd = -1;
};

} /* namespace lttng */

#endif /* LTTNG_FILE_DESCRIPTOR_HPP */
