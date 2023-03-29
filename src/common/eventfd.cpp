/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "eventfd.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/readwrite.hpp>

#include <sys/eventfd.h>

lttng::eventfd::eventfd(bool use_semaphore_semantics, std::uint64_t initial_value) :
	file_descriptor([use_semaphore_semantics, initial_value]() {
		int flags = ::EFD_CLOEXEC;

		if (use_semaphore_semantics) {
			flags |= ::EFD_SEMAPHORE;
		}

		const auto raw_fd = ::eventfd(initial_value, flags);
		if (raw_fd < 0) {
			LTTNG_THROW_POSIX("Failed to create eventfd", errno);
		}

		return raw_fd;
	}())
{
}

void lttng::eventfd::increment(std::uint64_t value)
{
	try {
		write(&value, sizeof(value));
	} catch (const std::exception& e) {
		LTTNG_THROW_ERROR(fmt::format("Failed to increment eventfd: {}", e.what()));
	}
}

std::uint64_t lttng::eventfd::decrement()
{
	std::uint64_t value;

	try {
		read(&value, sizeof(value));
	} catch (const std::exception& e) {
		LTTNG_THROW_ERROR(fmt::format("Failed to decrement eventfd: {}", e.what()));
	}

	return value;
}
