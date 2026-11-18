/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_COMMON_MINT_HPP
#define LTTNG_COMMON_MINT_HPP

#include <common/format.hpp>
#include <common/term-utils.hpp>

#include <string>
#include <utility>

namespace lttng {

/*
 * Wraps mint::mint() from `vendor/mint.hpp`, automatically determining
 * the `when` parameter from the `LTTNG_TERM_COLOR`, `NO_COLOR`, and
 * `FORCE_COLOR` environment variables.
 *
 * See lttng(1) to learn more about those environment variables.
 *
 * This function checks the environment variables once on first call.
 *
 * When the environment variables don't force a decision, this function
 * emits SGR codes if `target_stream` is connected to a terminal which
 * seems to support them.
 *
 * This function doesn't throw when the viewed string contains a
 * markup error, preferring to return a string containing the error
 * message instead.
 */
std::string
mint(const char *begin, const char *end, term_stream target_stream = term_stream::STANDARD_OUTPUT);

/*
 * Overload with a C string.
 */
inline std::string mint(const char *const str,
			const term_stream stream = term_stream::STANDARD_OUTPUT)
{
	return mint(str, str + std::strlen(str), stream);
}

/*
 * Overload with a C++ string.
 */
inline std::string mint(const std::string& str,
			const term_stream stream = term_stream::STANDARD_OUTPUT)
{
	return mint(str.data(), str.data() + str.size(), stream);
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
 * Like mint_format(), but for a string which the caller writes
 * to `stream`.
 */
template <typename... FormattingArguments>
std::string
mint_format(const term_stream stream, const std::string& fmtstr, FormattingArguments&&...args)
{
	return lttng::format(mint(fmtstr, stream), std::forward<FormattingArguments>(args)...);
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
