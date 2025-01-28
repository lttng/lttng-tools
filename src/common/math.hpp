/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MATH_HPP
#define LTTNG_MATH_HPP

#include <type_traits>

namespace lttng {
namespace math {
template <typename IntegralType>
bool is_power_of_two(IntegralType value)
{
	static_assert(std::is_integral<IntegralType>::value,
		      "IntegralType must be an integral type.");
	if (value < 0) {
		return false;
	}

	return __builtin_popcount(value) == 1;
}
} /* namespace math */
} /* namespace lttng */

#endif /* LTTNG_MATH_HPP */
