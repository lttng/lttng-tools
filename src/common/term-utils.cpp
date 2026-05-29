/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <common/term-utils.hpp>

#include <limits>
#include <mutex>
#include <sys/ioctl.h>
#include <unistd.h>

std::size_t lttng::term_columns() noexcept
{
	static std::once_flag init_flag;
	static std::size_t width = std::numeric_limits<std::size_t>::max();

	std::call_once(init_flag, [] {
		struct winsize ws;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
			width = ws.ws_col;
		}
	});

	return width;
}
