/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_COMMON_MINT_HPP
#define LTTNG_COMMON_MINT_HPP

#include <common/format.hpp>

#include <string>
#include <utility>

namespace lttng {

/*
 * Wraps mint::mint() from `vendor/mint.hpp`, automatically determining
 * the `when` parameter from the `LTTNG_TERM_COLOR` and `NO_COLOR`
 * environment variables.
 *
 * See lttng(1) to learn more about the `LTTNG_TERM_COLOR` and
 * `NO_COLOR` environment variables.
 *
 * This function checks the environment variables once on first call.
 *
 * This function doesn't throw when the viewed string contains a markup
 * error, preferring to return a string containing the error
 * message instead.
 */
std::string mint(const char *begin, const char *end);

/*
 * Overload with a C string.
 */
inline std::string mint(const char *const str)
{
	return mint(str, str + std::strlen(str));
}

/*
 * Overload with a C++ string.
 */
inline std::string mint(const std::string& str)
{
	return mint(str.data(), str.data() + str.size());
}

/*
 * Wraps mint::escape() from `vendor/mint.hpp`.
 */
std::string mint_escape(const char *begin, const char *end);

/*
 * Overload with a C string.
 */
inline std::string mint_escape(const char *const str)
{
	return mint_escape(str, str + std::strlen(str));
}

/*
 * Overload with a C++ string.
 */
inline std::string mint_escape(const std::string& str)
{
	return mint_escape(str.data(), str.data() + str.size());
}

/*
 * Wraps mint::escapeAnsi() from `vendor/mint.hpp`.
 */
std::string mint_escape_ansi(const char *begin, const char *end);

/*
 * Overload with a C string.
 */
inline std::string mint_escape_ansi(const char *const str)
{
	return mint_escape_ansi(str, str + std::strlen(str));
}

/*
 * Overload with a C++ string.
 */
inline std::string mint_escape_ansi(const std::string& str)
{
	return mint_escape_ansi(str.data(), str.data() + str.size());
}

/*
 * Uses mint() to transform `fmtStr`, and then passes it to
 * lttng::format() with the forwarded arguments.
 */
template <typename... FormattingArguments>
std::string mint_format(const std::string& fmtstr, FormattingArguments&&...args)
{
	return lttng::format(mint(fmtstr), std::forward<FormattingArguments>(args)...);
}

/*
 * Uses mint() to transform `fmtStr`, and then passes it to
 * lttng::print() with the forwarded arguments.
 */
template <typename... FormattingArguments>
void mint_print(const std::string& fmtstr, FormattingArguments&&...args)
{
	lttng::print(mint(fmtstr), std::forward<FormattingArguments>(args)...);
}

} /* namespace lttng */

#endif /* LTTNG_COMMON_MINT_HPP */
