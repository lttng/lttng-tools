/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "mint.hpp"

#include <common/mint.hpp>

#include <vendor/mint.hpp>

#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace lttng {
namespace {

/*
 * Returns the `mint::When` value from the `LTTNG_TERM_COLOR` environment
 * variable, caching the result.
 *
 * `LTTNG_TERM_COLOR` overrides `NO_COLOR` and `FORCE_COLOR`, which
 * mint::mint() only honors in its automatic mode.
 */
mint::When when() noexcept
{
	static const auto when_value = []() -> mint::When {
		const auto term_color = std::getenv("LTTNG_TERM_COLOR");

		if (term_color && std::strcmp(term_color, "always") == 0) {
			return mint::When::Always;
		}

		if (term_color && std::strcmp(term_color, "never") == 0) {
			return mint::When::Never;
		}

		return mint::When::Auto;
	}();

	return when_value;
}

} /* namespace */

std::string mint(const char *const begin, const char *const end, const term_stream target_stream)
{
	try {
		return mint::mint(begin, end, when(), term_stream_fd(target_stream));
	} catch (const std::runtime_error& ex) {
		return std::string{ "mint() parsing error: " } + ex.what();
	}
}

std::string mint_escape(const char *const begin, const char *const end)
{
	return mint::escape(begin, end);
}

std::string mint_escape_ansi(const char *const begin, const char *const end)
{
	return mint::escapeAnsi(begin, end);
}

} /* namespace lttng */
