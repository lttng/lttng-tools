/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_TIMERFD_HPP
#define LTTNG_TIMERFD_HPP

#include <common/stream-descriptor.hpp>

#include <chrono>
#include <cstdint>
#include <sys/timerfd.h>
#include <time.h>

namespace lttng {

class timerfd : public stream_descriptor {
public:
	/* Throws a posix_error exception on failure to create the underlying resource. */
	explicit timerfd(int flags = ::TFD_CLOEXEC);
	timerfd(const timerfd&) = delete;
	timerfd& operator=(const timerfd&) = delete;
	timerfd(timerfd&&) = delete;
	timerfd& operator=(timerfd&&) = delete;
	~timerfd() override = default;

	using stream_descriptor::fd;

	/*
	 * Set the timer to expire at the given time point (absolute), or after a duration
	 * (relative). Throws on error.
	 */
	void settime(std::chrono::steady_clock::time_point abs_time);
	void settime(std::chrono::nanoseconds rel_time);

	/*
	 * Reset an expired timer.
	 *
	 * Note that this will block until the timer expires if the timerfd has
	 * not expired yet.
	 */
	void reset();
};

} /* namespace lttng */

#endif /* LTTNG_TIMERFD_HPP */
