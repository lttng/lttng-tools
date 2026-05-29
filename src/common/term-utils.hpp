/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_COMMON_TERM_UTILS_HPP
#define LTTNG_COMMON_TERM_UTILS_HPP

#include <cstddef>

namespace lttng {

/*
 * Returns the terminal width (in columns) of the standard output, caching
 * the result on the first call.
 *
 * If the terminal width can't be determined (for example, when standard
 * output isn't a TTY), returns `std::numeric_limits<std::size_t>::max()`.
 */
std::size_t term_columns() noexcept;

} /* namespace lttng */

#endif /* LTTNG_COMMON_TERM_UTILS_HPP */
