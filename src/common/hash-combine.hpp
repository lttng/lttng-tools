/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_HASH_COMBINE_HPP
#define LTTNG_COMMON_HASH_COMBINE_HPP

#include <cstddef>

namespace lttng {
namespace utils {

/*
 * Combine `value` into the running hash `seed` using the
 * boost::hash_combine recipe.
 */
inline std::size_t hash_combine(std::size_t seed, std::size_t value) noexcept
{
	constexpr auto golden_ratio = sizeof(std::size_t) == 8 ? std::size_t(0x9e3779b97f4a7c15) :
								 std::size_t(0x9e3779b9);

	return seed ^ (value + golden_ratio + (seed << 6) + (seed >> 2));
}

} /* namespace utils */
} /* namespace lttng */

#endif /* LTTNG_COMMON_HASH_COMBINE_HPP */
