/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/math.hpp>

#include <cstdint>
#include <limits>
#include <tap/tap.h>

namespace {
const int test_count = 18;

void test_is_power_of_two_unsigned()
{
	ok(!lttng::math::is_power_of_two(std::uint64_t(0)), "0 isn't a power of two");
	ok(lttng::math::is_power_of_two(std::uint64_t(1)), "1 is a power of two");
	ok(lttng::math::is_power_of_two(std::uint64_t(2)), "2 is a power of two");
	ok(!lttng::math::is_power_of_two(std::uint64_t(3)), "3 isn't a power of two");
	ok(lttng::math::is_power_of_two(std::uint64_t(4096)), "4096 is a power of two");
	ok(!lttng::math::is_power_of_two(std::uint64_t(4095)), "4095 isn't a power of two");
	ok(lttng::math::is_power_of_two(std::uint8_t(128)), "128 (8-bit) is a power of two");
	ok(!lttng::math::is_power_of_two(std::numeric_limits<std::uint64_t>::max()),
	   "UINT64_MAX isn't a power of two");
}

/* Bits above the 32 least significant ones must count. */
void test_is_power_of_two_64_bit()
{
	ok(lttng::math::is_power_of_two(std::uint64_t(1) << 32), "2^32 is a power of two");
	ok(lttng::math::is_power_of_two(std::uint64_t(1) << 40), "2^40 is a power of two");
	ok(lttng::math::is_power_of_two(std::uint64_t(1) << 63), "2^63 is a power of two");
	ok(!lttng::math::is_power_of_two((std::uint64_t(1) << 32) | 1),
	   "2^32 + 1 isn't a power of two");
	ok(!lttng::math::is_power_of_two((std::uint64_t(1) << 32) | 2),
	   "2^32 + 2 isn't a power of two");
}

void test_is_power_of_two_signed()
{
	ok(!lttng::math::is_power_of_two(-1), "-1 isn't a power of two");
	ok(!lttng::math::is_power_of_two(-4), "-4 isn't a power of two");
	ok(!lttng::math::is_power_of_two(std::numeric_limits<std::int32_t>::min()),
	   "INT32_MIN isn't a power of two");
	ok(lttng::math::is_power_of_two(std::int64_t(1) << 62), "2^62 (signed) is a power of two");
	ok(!lttng::math::is_power_of_two(6), "6 isn't a power of two");
}
} /* namespace */

int main()
{
	plan_tests(test_count);

	test_is_power_of_two_unsigned();
	test_is_power_of_two_64_bit();
	test_is_power_of_two_signed();

	return exit_status();
}
