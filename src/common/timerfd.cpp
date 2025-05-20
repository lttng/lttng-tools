/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/timerfd.hpp>

#include <cerrno>
#include <cstring>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace lttng {

timerfd::timerfd(int flags) :
	file_descriptor([flags]() {
		const auto raw_fd = ::timerfd_create(CLOCK_MONOTONIC, flags);

		if (raw_fd < 0) {
			LTTNG_THROW_POSIX("Failed to create timerfd", errno);
		}

		return raw_fd;
	}()),
	stream_descriptor(fd())
{
}

void timerfd::settime(std::chrono::steady_clock::time_point abs_time)
{
	const auto now = std::chrono::steady_clock::now();
	const auto relative = abs_time > now ? abs_time - now : std::chrono::nanoseconds{ 0 };

	settime(relative);
}

void timerfd::settime(std::chrono::nanoseconds relative_time)
{
	DBG_FMT("Setting timerfd time: relative_time={}", relative_time);
	itimerspec spec{};

	spec.it_value.tv_sec =
		std::chrono::duration_cast<std::chrono::seconds>(relative_time).count();
	spec.it_value.tv_nsec = (relative_time % std::chrono::seconds(1)).count();

	if (::timerfd_settime(fd(), 0, &spec, nullptr) == -1) {
		LTTNG_THROW_POSIX(lttng::format("Failed to set timerfd time: relative_time={}",
						relative_time),
				  errno);
	}
}

void timerfd::reset()
{
	DBG("Resetting timerfd");

	std::uint64_t expiration_count;
	read(&expiration_count, sizeof(expiration_count));
}

} /* namespace lttng */
