/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENTFD_HPP
#define LTTNG_EVENTFD_HPP

#include <common/file-descriptor.hpp>

#include <cstdint>

namespace lttng {

class eventfd : public file_descriptor {
public:
	/* Throws a posix_error exception on failure to create the underlying resource. */
	eventfd(bool use_semaphore_semantics = true, std::uint64_t initial_value = 0);
	eventfd(const eventfd&) = delete;
	eventfd& operator=(const eventfd&) = delete;
	eventfd(eventfd&&) = delete;
	void operator=(eventfd&&) = delete;

	/* Throws on error. */
	void increment(std::uint64_t value = 1);
	/*
	 * Note that decrement() will block if the underlying value of the eventfd is 0 when
	 * semaphore semantics are used, see EVENTFD(2).
	 *
	 * decrement() returns the new value of the underlying counter of the eventfd.
	 *
	 * Throws on error.
	 */
	std::uint64_t decrement();
};

} /* namespace lttng */

#endif /* LTTNG_EVENTFD_HPP */
