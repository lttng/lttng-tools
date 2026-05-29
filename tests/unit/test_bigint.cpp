/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/bigint.hpp>

#include <limits>
#include <string>
#include <tap/tap.h>
#include <utility>

namespace {

/*
 * Checks that the canonical string of `bigint` is exactly `expected`.
 */
void check_str(const lttng::bigint& bigint, const std::string& expected, const std::string& what)
{
	ok(bigint.str() == expected,
	   "%s: got `%s`, expecting `%s`",
	   what.c_str(),
	   bigint.str().c_str(),
	   expected.c_str());
}

/*
 * Tests that construction from a default value, native integers, and
 * decimal strings yields the expected canonical representation,
 * including normalization of leading zeros and `-0`.
 */
void test_construction()
{
	diag("Construction");

	/* Default value is zero */
	check_str(lttng::bigint(), "0", "default constructor yields `0`");

	/* From native integers */
	check_str(lttng::bigint(0), "0", "from zero integer");
	check_str(lttng::bigint(42), "42", "from positive integer");
	check_str(lttng::bigint(-42), "-42", "from negative integer");
	check_str(lttng::bigint(1U), "1", "from unsigned integer");

	/*
	 * The most-negative value of a signed type: negating the
	 * magnitude would overflow, so this exercises the
	 * std::to_string() path that handles it correctly.
	 */
	check_str(lttng::bigint(std::numeric_limits<long long>::min()),
		  std::to_string(std::numeric_limits<long long>::min()),
		  "from most-negative `long long`");
	check_str(lttng::bigint(std::numeric_limits<unsigned long long>::max()),
		  std::to_string(std::numeric_limits<unsigned long long>::max()),
		  "from largest `unsigned long long`");

	/* From strings */
	check_str(lttng::bigint(std::string("123")), "123", "from positive string");
	check_str(lttng::bigint(std::string("-123")), "-123", "from negative string");

	/* Normalization: leading zeros are stripped */
	check_str(lttng::bigint(std::string("007")), "7", "leading zeros stripped");
	check_str(lttng::bigint(std::string("-007")), "-7", "leading zeros stripped (negative)");
	check_str(lttng::bigint(std::string("0000")), "0", "all zeros collapse to `0`");
	check_str(lttng::bigint(std::string("-0")), "0", "minus zero normalizes to `0`");
	check_str(lttng::bigint(std::string("-0000")), "0", "minus all zeros normalizes to `0`");
}

/*
 * Checks that grouped_str() of `bigint` with `separator` and
 * `group_four_digits` is exactly `expected`.
 */
void check_grouped(const lttng::bigint& bigint,
		   const char sep,
		   const bool group_four_digits,
		   const std::string& expected,
		   const std::string& what)
{
	const auto got = bigint.grouped_str(sep, group_four_digits);

	ok(got == expected,
	   "%s: got `%s`, expecting `%s`",
	   what.c_str(),
	   got.c_str(),
	   expected.c_str());
}

/*
 * Tests grouped_str(): digit grouping from the right, the optional
 * leading `-`, the four-digit special case, custom separators, and the
 * default arguments.
 */
void test_grouped_str()
{
	diag("Grouped digits string");

	/*
	 * Zero and magnitudes too small to group are
	 * returned unchanged.
	 */
	check_grouped(lttng::bigint(0), ',', false, "0", "zero");
	check_grouped(lttng::bigint(5), ',', false, "5", "single digit");
	check_grouped(lttng::bigint(42), ',', false, "42", "two digits");
	check_grouped(lttng::bigint(123), ',', false, "123", "three digits");

	/* Exactly four digits, ungrouped */
	check_grouped(lttng::bigint(1234), ',', false, "1234", "four digits ungrouped by default");
	check_grouped(lttng::bigint(-5678),
		      ',',
		      false,
		      "-5678",
		      "negative four digits ungrouped by default");

	/* Five or more digits are grouped */
	check_grouped(lttng::bigint(12345), ',', false, "12,345", "five digits");
	check_grouped(lttng::bigint(123456), ',', false, "123,456", "six digits");
	check_grouped(lttng::bigint(1234567), ',', false, "1,234,567", "seven digits");
	check_grouped(lttng::bigint(1000000), ',', false, "1,000,000", "round seven digits");

	/* Negative values keep the leading `-` outside the grouping */
	check_grouped(lttng::bigint(-12345), ',', false, "-12,345", "negative five digits");
	check_grouped(lttng::bigint(-1234567), ',', false, "-1,234,567", "negative seven digits");

	/* Arbitrary precision beyond the 64-bit range */
	check_grouped(lttng::bigint(std::string("123456789012345678901234567890")),
		      ',',
		      false,
		      "123,456,789,012,345,678,901,234,567,890",
		      "arbitrary-precision grouping");
	check_grouped(lttng::bigint(std::string("-123456789012345678901234567890")),
		      ',',
		      false,
		      "-123,456,789,012,345,678,901,234,567,890",
		      "negative arbitrary-precision grouping");

	/* Four-digit grouping enabled */
	check_grouped(lttng::bigint(1234), ',', true, "1,234", "four digits grouped when enabled");
	check_grouped(lttng::bigint(-5678),
		      ',',
		      true,
		      "-5,678",
		      "negative four digits grouped when enabled");

	/* Enabling four-digit grouping does not affect other magnitudes */
	check_grouped(lttng::bigint(123),
		      ',',
		      true,
		      "123",
		      "three digits unaffected when four-digit grouping enabled");
	check_grouped(lttng::bigint(12345),
		      ',',
		      true,
		      "12,345",
		      "five digits unaffected when four-digit grouping enabled");

	/* Custom separator */
	check_grouped(lttng::bigint(1234567), '.', false, "1.234.567", "custom `.` separator");
	check_grouped(lttng::bigint(1234567), ' ', false, "1 234 567", "custom space separator");
	check_grouped(lttng::bigint(1234),
		      '.',
		      true,
		      "1.234",
		      "custom separator with four-digit grouping");

	/* Default arguments: `,` separator, four digits left ungrouped */
	ok(lttng::bigint(1234567).grouped_str() == "1,234,567", "default arguments group with `,`");
	ok(lttng::bigint(1234).grouped_str() == "1234",
	   "default arguments leave four digits ungrouped");
}

/*
 * Tests assignment from native integers and strings (with
 * normalization), as well as copy and move assignment.
 */
void test_assignment()
{
	diag("Assignment");

	lttng::bigint bigint;

	bigint = 55;
	check_str(bigint, "55", "assign from positive integer");

	bigint = -77;
	check_str(bigint, "-77", "assign from negative integer");

	bigint = std::string("0099");
	check_str(bigint, "99", "assign from string with leading zeros");

	bigint = std::string("-0");
	check_str(bigint, "0", "assign from minus zero string");

	/* Copy assignment */
	{
		const lttng::bigint source(std::string("123456789"));
		lttng::bigint copy;

		copy = source;
		check_str(copy, "123456789", "copy assignment");
		ok(source == copy, "copy is equal to source after copy assignment");
	}

	/* Move assignment */
	lttng::bigint to_move(std::string("987654321"));
	lttng::bigint moved;

	moved = std::move(to_move);
	check_str(moved, "987654321", "move assignment");
}

/*
 * Tests that unary minus flips the sign of non-zero values, leaves zero
 * as `0` (never `-0`), and round-trips through double negation.
 */
void test_unary_minus()
{
	diag("Unary minus");

	check_str(-lttng::bigint(42), "-42", "negate positive");
	check_str(-lttng::bigint(-42), "42", "negate negative");
	check_str(-lttng::bigint(0), "0", "negate zero stays `0` (not `-0`)");
	check_str(-(-lttng::bigint(7)), "7", "double negation");
}

/*
 * Tests addition for same and different signs, cancellation to zero,
 * carry propagation past the 64-bit range, mixed `lttng::bigint`/native
 * operands in both orders, and the operator+=() compound operator.
 */
void test_addition()
{
	diag("Addition");

	check_str(lttng::bigint(0) + lttng::bigint(0), "0", "`0` + `0`");
	check_str(lttng::bigint(2) + lttng::bigint(3), "5", "positive + positive");
	check_str(lttng::bigint(-2) + lttng::bigint(-3), "-5", "negative + negative");

	/* Different signs: result takes the sign of the larger magnitude */
	check_str(
		lttng::bigint(10) + lttng::bigint(-3), "7", "positive + negative (positive wins)");
	check_str(
		lttng::bigint(3) + lttng::bigint(-10), "-7", "positive + negative (negative wins)");
	check_str(
		lttng::bigint(-10) + lttng::bigint(3), "-7", "negative + positive (negative wins)");
	check_str(lttng::bigint(5) + lttng::bigint(-5), "0", "opposite values cancel to `0`");

	/* Carry propagation */
	check_str(lttng::bigint(999) + lttng::bigint(1), "1000", "carry propagates across digits");
	check_str(lttng::bigint(std::string("99999999999999999999")) + lttng::bigint(1),
		  "100000000000000000000",
		  "carry beyond 64-bit range");

	/* Arbitrary precision: both operands beyond 64-bit range */
	check_str(lttng::bigint(std::string("123456789012345678901234567890")) +
			  lttng::bigint(std::string("987654321098765432109876543210")),
		  "1111111110111111111011111111100",
		  "arbitrary-precision addition");

	/* With native integers, both operand orders */
	check_str(lttng::bigint(100) + 23, "123", "`lttng::bigint` + integer");
	check_str(23 + lttng::bigint(100), "123", "integer + `lttng::bigint`");

	/* Compound assignment */
	lttng::bigint accumulator(0);

	accumulator += lttng::bigint(5);
	accumulator += 10;
	check_str(accumulator, "15", "operator+=() with `lttng::bigint` then integer");
}

/*
 * Tests subtraction for the resulting sign, cancellation to zero,
 * borrow propagation past the 64-bit range, mixed
 * `lttng::bigint`/native operands in both orders (where order matters),
 * and the operator-=() compound operator.
 */
void test_subtraction()
{
	diag("Subtraction");

	check_str(lttng::bigint(0) - lttng::bigint(0), "0", "`0` - `0`");
	check_str(lttng::bigint(5) - lttng::bigint(3), "2", "positive - smaller positive");
	check_str(lttng::bigint(3) - lttng::bigint(5), "-2", "positive - larger positive");
	check_str(lttng::bigint(7) - lttng::bigint(7), "0", "equal values cancel to `0`");

	/* Subtracting a negative is adding */
	check_str(lttng::bigint(5) - lttng::bigint(-3), "8", "minus a negative adds");
	check_str(lttng::bigint(-5) - lttng::bigint(-3), "-2", "negative - negative");

	/* Borrow propagation */
	check_str(lttng::bigint(1000) - lttng::bigint(1), "999", "borrow propagates across digits");
	check_str(lttng::bigint(std::string("100000000000000000000")) - lttng::bigint(1),
		  "99999999999999999999",
		  "borrow beyond 64-bit range");

	/* With native integers, both operand orders */
	check_str(lttng::bigint(100) - 23, "77", "`lttng::bigint` - integer");
	check_str(23 - lttng::bigint(100), "-77", "integer - `lttng::bigint` (order matters)");

	/* Compound assignment */
	lttng::bigint value(20);

	value -= lttng::bigint(5);
	value -= 3;
	check_str(value, "12", "operator-=() with `lttng::bigint` then integer");
}

/*
 * Tests the pre/post increment and decrement operators, checking both
 * the returned value and the in-place mutation, including
 * crossing zero.
 */
void test_increment_decrement()
{
	diag("Increment and decrement");

	lttng::bigint value(5);

	check_str(++value, "6", "pre-increment yields new value");
	check_str(value, "6", "pre-increment mutates");

	check_str(value++, "6", "post-increment yields previous value");
	check_str(value, "7", "post-increment mutates");

	check_str(--value, "6", "pre-decrement yields new value");
	check_str(value--, "6", "post-decrement yields previous value");
	check_str(value, "5", "post-decrement mutates");

	/* Crossing zero */
	lttng::bigint zero(0);

	check_str(--zero, "-1", "decrement past zero goes negative");
	check_str(++zero, "0", "increment back to `0` (not `-0`)");
}

/*
 * Checks the six comparison operators for `smaller` < `larger`, using
 * both `lttng::bigint`/`lttng::bigint` and the mixed
 * `lttng::bigint`/native overloads.
 */
void check_ordering(const lttng::bigint& smaller, long long larger, const std::string& what)
{
	const lttng::bigint larger_big(larger);

	/* `lttng::bigint` vs `lttng::bigint` */
	ok(smaller < larger_big, "%s: smaller < larger", what.c_str());
	ok(smaller <= larger_big, "%s: smaller ≤ larger", what.c_str());
	ok(larger_big > smaller, "%s: larger > smaller", what.c_str());
	ok(larger_big >= smaller, "%s: larger ≥ smaller", what.c_str());
	ok(smaller != larger_big, "%s: smaller != larger", what.c_str());
	ok(!(smaller == larger_big), "%s: not (smaller == larger)", what.c_str());

	/* `lttng::bigint` vs native integer (both operand orders) */
	ok(smaller < larger, "%s: `lttng::bigint` < integer", what.c_str());
	ok(larger > smaller, "%s: integer > `lttng::bigint`", what.c_str());
	ok(smaller <= larger, "%s: `lttng::bigint` ≤ integer", what.c_str());
	ok(larger >= smaller, "%s: integer ≥ `lttng::bigint`", what.c_str());
}

/*
 * Tests the six comparison operators for both bigint/bigint and mixed
 * bigint/native operands, covering sign-dominates-magnitude ordering
 * and arbitrary-precision values.
 */
void test_comparison()
{
	diag("Comparison");

	/* Equality */
	ok(lttng::bigint(42) == lttng::bigint(42), "equal positives compare equal");
	ok(lttng::bigint(-42) == lttng::bigint(-42), "equal negatives compare equal");
	ok(lttng::bigint(0) == lttng::bigint(0), "zeros compare equal");
	ok(lttng::bigint(std::string("-0")) == lttng::bigint(0), "minus zero equals zero");

	/* Equality with native integers, both orders */
	ok(lttng::bigint(42) == 42, "`lttng::bigint` == integer");
	ok(7 == lttng::bigint(7), "integer == `lttng::bigint`");
	ok(lttng::bigint(42) != 43, "`lttng::bigint` != integer");
	ok(43 != lttng::bigint(42), "integer != `lttng::bigint`");

	/* Orderings */
	check_ordering(lttng::bigint(1), 2, "`1` < `2`");
	check_ordering(lttng::bigint(-2), -1, "`-2` < `-1`");
	check_ordering(lttng::bigint(-1), 1, "`-1` < `1` (sign dominates)");
	check_ordering(lttng::bigint(-5), 0, "`-5` < `0`");
	check_ordering(lttng::bigint(0), 5, "`0` < `5`");

	/* Magnitude ordering across different digit counts */
	check_ordering(lttng::bigint(99), 100, "fewer digits is smaller");

	/* operator()<= and operator()>= hold for equal values */
	ok(lttng::bigint(8) <= lttng::bigint(8), "operator<=() holds for equal values");
	ok(lttng::bigint(8) >= lttng::bigint(8), "operator>=() holds for equal values");

	/* Arbitrary-precision ordering beyond 64-bit range */
	ok(lttng::bigint(std::string("99999999999999999999999999999998")) <
		   lttng::bigint(std::string("99999999999999999999999999999999")),
	   "arbitrary-precision less-than");
}

} /* namespace */

int main()
{
	plan_tests(152);
	diag("`lttng::bigint` unit tests");

	/* Tests */
	test_construction();
	test_grouped_str();
	test_assignment();
	test_unary_minus();
	test_addition();
	test_subtraction();
	test_increment_decrement();
	test_comparison();

	/* Done */
	return exit_status();
}
