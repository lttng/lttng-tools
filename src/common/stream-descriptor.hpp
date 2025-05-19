/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_STREAM_DESCRIPTOR_HPP
#define LTTNG_STREAM_DESCRIPTOR_HPP

#include "file-descriptor.hpp"

#include <utility>

namespace lttng {

class input_stream_descriptor : public virtual file_descriptor {
public:
	using file_descriptor::file_descriptor;

	/*
	 * gcc 4.8.5 has incomplete support for inheriting constructors forcing
	 * us to define this constructor explicitly.
	 */
	explicit input_stream_descriptor(int raw_fd) noexcept : file_descriptor(raw_fd)
	{
	}

	~input_stream_descriptor() override = default;
	input_stream_descriptor(const input_stream_descriptor&) = delete;
	input_stream_descriptor& operator=(const input_stream_descriptor& other) = delete;
	input_stream_descriptor(input_stream_descriptor&&) noexcept = default;

	input_stream_descriptor& operator=(input_stream_descriptor&& other) noexcept
	{
		if (this != &other) {
			/*
			 * Move assign virtual base "file_descriptor" and silence
			 * Wvirtual-move-assign.
			 */
			file_descriptor::operator=(std::move(other));
		}

		return *this;
	}

	/*
	 * Read `size` bytes from the underlying file descriptor, assuming
	 * raw_fd behaves as a blocking device.
	 *
	 * Throws an exception if the requested amount of bytes couldn't be read.
	 */
	void read(void *buffer, std::size_t size);
};

class output_stream_descriptor : public virtual file_descriptor {
public:
	using file_descriptor::file_descriptor;

	/*
	 * gcc 4.8.5 has incomplete support for inheriting constructors forcing
	 * us to define this constructor explicitly.
	 */
	explicit output_stream_descriptor(int raw_fd) noexcept : file_descriptor(raw_fd)
	{
	}

	~output_stream_descriptor() override = default;
	output_stream_descriptor(const output_stream_descriptor&) = delete;
	output_stream_descriptor& operator=(const output_stream_descriptor& other) = delete;
	output_stream_descriptor(output_stream_descriptor&&) noexcept = default;
	output_stream_descriptor& operator=(output_stream_descriptor&& other) noexcept
	{
		if (this != &other) {
			/*
			 * Move assign virtual base "file_descriptor" and silence
			 * Wvirtual-move-assign.
			 */
			file_descriptor::operator=(std::move(other));
		}

		return *this;
	}

	/*
	 * Write `size` bytes to the underlying file descriptor, assuming
	 * raw_fd behaves as a blocking device.
	 *
	 * Throws an exception if the requested amount of bytes couldn't be written.
	 */
	void write(const void *buffer, std::size_t size);
};

class stream_descriptor : public input_stream_descriptor, public output_stream_descriptor {
public:
	explicit stream_descriptor(int raw_fd) noexcept :
		file_descriptor(raw_fd),
		input_stream_descriptor(raw_fd),
		output_stream_descriptor(raw_fd)
	{
	}
};

} /* namespace lttng */

#endif /* LTTNG_STREAM_DESCRIPTOR_HPP */
