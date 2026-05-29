/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_BIGINT_HPP
#define LTTNG_BIGINT_HPP

#include <common/macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <type_traits>
#include <utility>

namespace lttng {

/*
 * Basic arbitrary-precision (infinite precision) signed integer.
 *
 * The value is kept as its canonical decimal representation in a
 * single `std::string`.
 *
 * Supports:
 *
 * • Construction from string or native integer.
 * • Assignment from string or native integer.
 * • String access with str().
 * • Grouped digits string creation with grouped_str().
 * • Comparison with big integer or native integer.
 * • Addition and subtraction with big integer or native integer.
 *
 * The internal string representation:
 *
 * • Has the most significant digit first.
 *
 * • May have a single leading `-` for a negative value.
 *
 * • Has no leading zeros, except for the value zero which is
 *   exactly `0`.
 *
 * • Is never `-0`.
 *
 * Arithmetic operations uses the schoolbook digit-by-digit algorithms
 * on the unsigned magnitudes, with the sign handled separately.
 */
class bigint final {
public:
	/*
	 * Builds a big integer having the value 0.
	 */
	bigint() = default;

	/*
	 * Builds a big integer from the integer `val`.
	 *
	 * std::to_string() yields a canonical representation for every
	 * integral type, including the most-negative value of a signed
	 * type (where negating the magnitude would overflow), and never
	 * emits leading zeros.
	 */
	template <typename IntType,
		  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
	explicit bigint(const IntType val) : _str(std::to_string(val))
	{
	}

	/*
	 * Builds a big integer from a decimal string: an optional
	 * single leading `-` followed by one or more decimal digits.
	 *
	 * `val` must be such a string.
	 */
	explicit bigint(std::string val) : _str(std::move(val))
	{
		_validate(_str);
		_normalize();
	}

	bigint(const bigint&) = default;
	bigint(bigint&&) noexcept = default;
	bigint& operator=(const bigint&) = default;
	bigint& operator=(bigint&&) noexcept = default;
	~bigint() = default;

	template <typename IntType,
		  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
	bigint& operator=(const IntType value)
	{
		return *this = bigint(value);
	}

	bigint& operator=(std::string val)
	{
		return *this = bigint(std::move(val));
	}

	/*
	 * The canonical decimal string representation of this value,
	 * starting with `-` if negative.
	 */
	const std::string& str() const noexcept
	{
		return _str;
	}

	/*
	 * The decimal string representation of this value with `sep`
	 * inserted every three digits from the right, preserving any
	 * leading `-`.
	 *
	 * When this value has exactly four digits (for example `2860`
	 * or `-1203`), this method only inserts the separator if
	 * `group_four_digits` is true. This follows the common
	 * typographic convention of leaving four-digit
	 * numbers ungrouped.
	 */
	std::string grouped_str(const char sep = ',', const bool group_four_digits = false) const
	{
		const auto digits_begin = _is_neg() ? 1U : 0U;
		const auto digit_count = _str.size() - digits_begin;

		/*
		 * With exactly four digits and grouping disabled for
		 * that case, return the canonical string as is.
		 */
		if (digit_count == 4 && !group_four_digits) {
			return _str;
		}

		std::string result;

		result.reserve(_str.size() + digit_count / 3);

		if (_is_neg()) {
			result += '-';
		}

		for (auto i = digits_begin; i < _str.size(); ++i) {
			if (i > digits_begin && (_str.size() - i) % 3 == 0) {
				result += sep;
			}

			result += _str[i];
		}

		return result;
	}

	bigint operator-() const
	{
		if (_is_zero()) {
			return *this;
		}

		bigint result = *this;

		if (result._str[0] == '-') {
			result._str.erase(result._str.begin());
		} else {
			result._str.insert(result._str.begin(), '-');
		}

		return result;
	}

	bigint& operator+=(const bigint& other)
	{
		const bool this_is_neg = _is_neg();

		if (this_is_neg == other._is_neg()) {
			/* Same sign: add magnitudes and keep the sign */
			_str = _add_magnitudes(_magnitude(), other._magnitude());
			_apply_sign(this_is_neg);
		} else {
			/*
			 * Different signs: subtract the smaller
			 * magnitude from the larger one; the result
			 * takes the sign of the larger magnitude.
			 */
			const auto this_magnitude = _magnitude();
			const auto other_magnitude = other._magnitude();
			const int comp = _compare_magnitudes(this_magnitude, other_magnitude);

			if (comp == 0) {
				_str = "0";
			} else if (comp > 0) {
				_str = _subtract_magnitudes(this_magnitude, other_magnitude);
				_apply_sign(this_is_neg);
			} else {
				_str = _subtract_magnitudes(other_magnitude, this_magnitude);
				_apply_sign(!this_is_neg);
			}
		}

		_normalize();
		return *this;
	}

	bigint& operator-=(const bigint& other)
	{
		return *this += -other;
	}

	template <typename IntType,
		  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
	bigint& operator+=(const IntType value)
	{
		return *this += bigint(value);
	}

	template <typename IntType,
		  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
	bigint& operator-=(IntType value)
	{
		return *this -= bigint(value);
	}

	bigint& operator++()
	{
		return *this += bigint(1);
	}

	bigint operator++(int)
	{
		bigint previous = *this;

		++*this;
		return previous;
	}

	bigint& operator--()
	{
		return *this -= bigint(1);
	}

	bigint operator--(int)
	{
		bigint previous = *this;

		--*this;
		return previous;
	}

	bool operator==(const bigint& other) const
	{
		return _compare(other) == 0;
	}

	bool operator!=(const bigint& other) const
	{
		return _compare(other) != 0;
	}

	bool operator<(const bigint& other) const
	{
		return _compare(other) < 0;
	}

	bool operator<=(const bigint& other) const
	{
		return _compare(other) <= 0;
	}

	bool operator>(const bigint& other) const
	{
		return _compare(other) > 0;
	}

	bool operator>=(const bigint& other) const
	{
		return _compare(other) >= 0;
	}

private:
	bool _is_neg() const noexcept
	{
		return _str[0] == '-';
	}

	bool _is_zero() const noexcept
	{
		return _str == "0";
	}

	/*
	 * The unsigned magnitude (the representation without any
	 * leading `-`).
	 */
	std::string _magnitude() const
	{
		return _is_neg() ? _str.substr(1) : _str;
	}

	/*
	 * Prepends `-` to `_str` when `is_neg` is true.
	 */
	void _apply_sign(const bool is_neg)
	{
		if (is_neg) {
			_str.insert(_str.begin(), '-');
		}
	}

	/*
	 * Brings `_str` back to canonical form: strips leading zeros
	 * and collapses any representation of zero (including `-0`,
	 * `-`, and the empty string) to `0`.
	 */
	void _normalize()
	{
		const bool is_neg = _is_neg();
		std::string mag = is_neg ? _str.substr(1) : _str;
		const auto first_significant = mag.find_first_not_of('0');

		if (first_significant == std::string::npos) {
			_str = "0";
			return;
		}

		mag.erase(0, first_significant);
		_str = is_neg ? "-" + mag : mag;
	}

	/*
	 * Asserts that `value` is an optional single leading `-`
	 * followed by one or more decimal digits.
	 */
	static void _validate(const std::string& value)
	{
		LTTNG_ASSERT(!value.empty());

		const std::size_t digits_start = value[0] == '-' ? 1 : 0;

		/* At least one digit after the optional sign. */
		LTTNG_ASSERT(value.size() > digits_start);

		for (std::size_t i = digits_start; i < value.size(); ++i) {
			LTTNG_ASSERT(value[i] >= '0' && value[i] <= '9');
		}
	}

	/*
	 * Returns a negative value, zero, or a positive value as this
	 * value is less than, equal to, or greater than `other`.
	 */
	int _compare(const bigint& other) const
	{
		const bool this_is_neg = _is_neg();

		/* A negative value is always less than a non-negative one */
		if (this_is_neg != other._is_neg()) {
			return this_is_neg ? -1 : 1;
		}

		/*
		 * Same sign: order by magnitude, reversing the result
		 * when both are negative (the larger magnitude is then
		 * the smaller value).
		 */
		const auto magnitude_comp = _compare_magnitudes(_magnitude(), other._magnitude());

		return this_is_neg ? -magnitude_comp : magnitude_comp;
	}

	/*
	 * Compares two magnitudes without leading zeros; returns -1, 0,
	 * or 1.
	 */
	static int _compare_magnitudes(const std::string& a, const std::string& b) noexcept
	{
		if (a.size() != b.size()) {
			return a.size() < b.size() ? -1 : 1;
		}

		if (a < b) {
			return -1;
		}

		return a > b ? 1 : 0;
	}

	/*
	 * Schoolbook addition of two unsigned magnitudes.
	 */
	static std::string _add_magnitudes(const std::string& a, const std::string& b)
	{
		std::string result;

		result.reserve(std::max(a.size(), b.size()) + 1);

		auto carry = 0;
		auto a_pos = a.size();
		auto b_pos = b.size();

		while (a_pos > 0 || b_pos > 0 || carry != 0) {
			auto sum = carry;

			if (a_pos > 0) {
				sum += a[--a_pos] - '0';
			}

			if (b_pos > 0) {
				sum += b[--b_pos] - '0';
			}

			result.push_back(static_cast<char>('0' + (sum % 10)));
			carry = sum / 10;
		}

		std::reverse(result.begin(), result.end());
		return result;
	}

	/*
	 * Schoolbook subtraction of two unsigned magnitudes.
	 *
	 * `larger` must be greater than or equal to `smaller`. The
	 * result may carry leading zeros; the caller normalizes.
	 */
	static std::string _subtract_magnitudes(const std::string& larger,
						const std::string& smaller)
	{
		std::string result;

		result.reserve(larger.size());

		auto borrow = 0;
		auto larger_pos = larger.size();
		auto smaller_pos = smaller.size();

		while (larger_pos > 0) {
			auto diff = (larger[--larger_pos] - '0') - borrow;

			if (smaller_pos > 0) {
				diff -= smaller[--smaller_pos] - '0';
			}

			if (diff < 0) {
				diff += 10;
				borrow = 1;
			} else {
				borrow = 0;
			}

			result.push_back(static_cast<char>('0' + diff));
		}

		std::reverse(result.begin(), result.end());
		return result;
	}

	std::string _str{ "0" };
};

inline bigint operator+(bigint lhs, const bigint& rhs)
{
	lhs += rhs;
	return lhs;
}

inline bigint operator-(bigint lhs, const bigint& rhs)
{
	lhs -= rhs;
	return lhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bigint operator+(bigint lhs, IntType rhs)
{
	lhs += bigint(rhs);
	return lhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bigint operator+(IntType lhs, bigint rhs)
{
	rhs += bigint(lhs);
	return rhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bigint operator-(bigint lhs, IntType rhs)
{
	lhs -= bigint(rhs);
	return lhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bigint operator-(IntType lhs, const bigint& rhs)
{
	/* `lhs - rhs`, not `rhs - lhs`. */
	bigint result(lhs);

	result -= rhs;
	return result;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator==(const bigint& lhs, IntType rhs)
{
	return lhs == bigint(rhs);
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator==(IntType lhs, const bigint& rhs)
{
	return bigint(lhs) == rhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator!=(const bigint& lhs, IntType rhs)
{
	return lhs != bigint(rhs);
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator!=(IntType lhs, const bigint& rhs)
{
	return bigint(lhs) != rhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator<(const bigint& lhs, IntType rhs)
{
	return lhs < bigint(rhs);
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator<(IntType lhs, const bigint& rhs)
{
	return bigint(lhs) < rhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator<=(const bigint& lhs, IntType rhs)
{
	return lhs <= bigint(rhs);
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator<=(IntType lhs, const bigint& rhs)
{
	return bigint(lhs) <= rhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator>(const bigint& lhs, IntType rhs)
{
	return lhs > bigint(rhs);
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator>(IntType lhs, const bigint& rhs)
{
	return bigint(lhs) > rhs;
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator>=(const bigint& lhs, IntType rhs)
{
	return lhs >= bigint(rhs);
}

template <typename IntType,
	  typename = typename std::enable_if<std::is_integral<IntType>::value>::type>
bool operator>=(IntType lhs, const bigint& rhs)
{
	return bigint(lhs) >= rhs;
}

} /* namespace lttng */

#endif /* LTTNG_BIGINT_HPP */
