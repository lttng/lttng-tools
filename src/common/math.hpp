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
bool is_power_of_two(const IntegralType value) noexcept
{
	static_assert(std::is_integral<IntegralType>::value,
		      "IntegralType must be an integral type.");
	return value > 0 && (value & (value - 1)) == 0;
}
} /* namespace math */
} /* namespace lttng */

#endif /* LTTNG_MATH_HPP */
