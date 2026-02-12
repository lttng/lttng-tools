/*
 * SPDX-FileCopyrightText: 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef LTTNG_C_STRING_VIEW_HPP
#define LTTNG_C_STRING_VIEW_HPP

#include <common/format.hpp>
#include <common/type-traits.hpp>

#include <cstddef>
#include <cstring>
#include <functional>
#include <string>

namespace lttng {

/*
 * A view on a constant null-terminated C string.
 */
class c_string_view final {
public:
	/*
	 * Builds an empty view (data() returns `nullptr`).
	 *
	 * Intentionally not explicit.
	 */
	constexpr c_string_view() noexcept = default;

	/*
	 * Builds a view of the C string `str` (may be `nullptr`).
	 *
	 * Intentionally not explicit.
	 */
	/* NOLINTBEGIN(google-explicit-constructor) */
	constexpr c_string_view(const char *const str) noexcept : _str{ str }
	{
	}
	/* NOLINTEND(google-explicit-constructor) */

	/*
	 * Builds a view of the string `str`.
	 */
	/* NOLINTBEGIN(google-explicit-constructor) */
	c_string_view(const std::string& str) noexcept : _str{ str.c_str() }
	{
	}
	/* NOLINTEND(google-explicit-constructor) */

	/*
	 * Makes this view view the C string `str` (may be `nullptr`).
	 */
	c_string_view& operator=(const char *const str) noexcept
	{
		_str = str;
		return *this;
	}

	/*
	 * Viewed null-terminated C string (may be `nullptr`).
	 */
	const char *data() const noexcept
	{
		return _str;
	}

	/*
	 * Alias of data().
	 */
	operator const char *() const noexcept /* NOLINT(google-explicit-constructor) */
	{
		return this->data();
	}

	/*
	 * Evaluate as boolean (false means an empty string).
	 */
	operator bool() const noexcept /* NOLINT(google-explicit-constructor) */
	{
		return this->data() && *this->data();
	}

	/*
	 * Alias of data().
	 */
	const char *operator*() const noexcept
	{
		return this->data();
	}

	/*
	 * Alias of data().
	 *
	 * data() must not return `nullptr`.
	 */
	const char *begin() const noexcept
	{
		return this->data();
	}

	/*
	 * Pointer to the null character of the viewed C string.
	 *
	 * data() must not return `nullptr`.
	 */
	const char *end() const noexcept
	{
		return _str + this->len();
	}

	/*
	 * Length of the viewed C string, excluding the null character.
	 *
	 * data() must not return `nullptr`.
	 */
	std::size_t len() const noexcept
	{
		return std::strlen(_str);
	}

	/*
	 * Returns an `std::string` instance containing a copy of the viewed
	 * C string.
	 *
	 * data() must not return `nullptr`.
	 */
	std::string str() const
	{
		return std::string{ _str };
	}

	/*
	 * Alias of str().
	 */
	operator std::string() const /* NOLINT(google-explicit-constructor) */
	{
		return this->str();
	}

	bool startsWith(const lttng::c_string_view prefix) const noexcept
	{
		return std::strncmp(_str, (const char *) prefix, prefix.len()) == 0;
	}

private:
	const char *_str = nullptr;
};

inline const char *format_as(const c_string_view& str)
{
	return str ? *str : "(null)";
}

namespace internal {

template <typename StrT>
const char *as_const_char_ptr(StrT&& val) noexcept
{
	return val.data();
}

inline const char *as_const_char_ptr(const char *const val) noexcept
{
	return val;
}

template <typename StrT>
using comparable_with_c_string_view = lttng::traits::
	is_one_of<typename std::decay<StrT>::type, c_string_view, std::string, const char *>;

} /* namespace internal */

/*
 * Returns true if `lhs` is equal to `rhs`.
 *
 * `LhsT` and `RhsT` may be any of:
 *
 * • `const char *`
 * • `std::string`
 * • `c_string_view`
 *
 * Both `lhs` and `rhs` must not have an underlying `nullptr` raw data.
 */
template <
	typename LhsT,
	typename RhsT,
	typename =
		typename std::enable_if<internal::comparable_with_c_string_view<LhsT>::value>::type,
	typename =
		typename std::enable_if<internal::comparable_with_c_string_view<RhsT>::value>::type>
bool operator==(LhsT&& lhs, RhsT&& rhs) noexcept
{
	const auto raw_lhs = internal::as_const_char_ptr(lhs);
	const auto raw_rhs = internal::as_const_char_ptr(rhs);

	if (raw_lhs == raw_rhs) {
		return true;
	} else if (!raw_lhs || !raw_rhs) {
		/* Only one of the strings is null, not equal. */
		return false;
	}

	return std::strcmp(raw_lhs, raw_rhs) == 0;
}

/*
 * Returns true if `lhs` is not equal to `rhs`.
 *
 * `LhsT` and `RhsT` may be any of:
 *
 * • `const char *`
 * • `std::string`
 * • `c_string_view`
 *
 * Both `lhs` and `rhs` must not have an underlying `nullptr` raw data.
 */
template <
	typename LhsT,
	typename RhsT,
	typename =
		typename std::enable_if<internal::comparable_with_c_string_view<LhsT>::value>::type,
	typename =
		typename std::enable_if<internal::comparable_with_c_string_view<RhsT>::value>::type>
bool operator!=(LhsT&& lhs, RhsT&& rhs) noexcept
{
	return !(std::forward<LhsT>(lhs) == std::forward<RhsT>(rhs));
}

} /* namespace lttng */

/*
 * Appends `rhs` to `lhs`.
 */
inline void operator+=(std::string& lhs, lttng::c_string_view rhs)
{
	lhs += rhs.data();
}

namespace std {
template <>
struct hash<lttng::c_string_view> {
	std::size_t operator()(const lttng::c_string_view& str) const
	{
		auto hash_value = std::hash<char>{}('\0');

		for (auto character : str) {
			hash_value ^= std::hash<decltype(character)>{}(character);
		}

		return hash_value;
	}
};
} /* namespace std */

#endif /* LTTNG_C_STRING_VIEW_HPP */
