/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_COMMON_TERM_UTILS_HPP
#define LTTNG_COMMON_TERM_UTILS_HPP

#include <cstddef>

namespace lttng {

/* Standard stream which may be connected to a terminal. */
enum class term_stream {
	STANDARD_OUTPUT,
	STANDARD_ERROR,
};

/*
 * Returns the terminal width (in columns) of `stream`, caching the result
 * on the first call for each stream.
 *
 * If the terminal width can't be determined (for example, when `stream`
 * isn't a TTY), returns `std::numeric_limits<std::size_t>::max()`.
 */
std::size_t term_columns(term_stream stream = term_stream::STANDARD_OUTPUT) noexcept;

/* Returns the file descriptor of `stream`. */
int term_stream_fd(term_stream stream) noexcept;

} /* namespace lttng */

#endif /* LTTNG_COMMON_TERM_UTILS_HPP */
