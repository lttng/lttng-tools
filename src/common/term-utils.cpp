/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <common/error.hpp>
#include <common/scope-exit.hpp>
#include <common/term-utils.hpp>

#include <cerrno>
#include <limits>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {
std::size_t read_term_columns(const int fd) noexcept
{
	struct winsize ws;

	if (ioctl(fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
		return ws.ws_col;
	}

	return std::numeric_limits<std::size_t>::max();
}
} /* namespace */

std::size_t lttng::term_columns(const term_stream stream) noexcept
{
	/*
	 * Since this is often used during error formatting, preserve the `errno` of the error
	 * being processed from both the ioctl and the wait on a concurrent static initialization.
	 */
	const auto saved_errno = errno;
	const lttng::scope_exit restore_errno([saved_errno]() noexcept { errno = saved_errno; });

	if (stream == term_stream::STANDARD_ERROR) {
		static const auto err_columns = read_term_columns(term_stream_fd(stream));

		return err_columns;
	}

	LTTNG_ASSERT(stream == term_stream::STANDARD_OUTPUT);
	static const auto out_columns = read_term_columns(term_stream_fd(stream));

	return out_columns;
}

int lttng::term_stream_fd(const term_stream stream) noexcept
{
	return stream == term_stream::STANDARD_ERROR ? STDERR_FILENO : STDOUT_FILENO;
}
