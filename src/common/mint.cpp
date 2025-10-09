/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "mint.hpp"

#include <vendor/mint.hpp>

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace lttng {
namespace {

/*
 * Returns the `mint::When` value from the `NO_COLOR` and
 * `LTTNG_TERM_COLOR` environment variables, caching the result.
 *
 * `NO_COLOR` overrides `LTTNG_TERM_COLOR`.
 */
mint::When when() noexcept
{
	static std::once_flag init_flag;
	static mint::When when_value = mint::When::Auto;

	std::call_once(init_flag, [] {
		/*
		 * Check `NO_COLOR` first (see <https://no-color.org/>).
		 *
		 * If set and not empty, disable colors.
		 */
		{
			const auto no_color = std::getenv("NO_COLOR");

			if (no_color && no_color[0] != '\0') {
				when_value = mint::When::Never;
				return;
			}
		}

		/* Check `LTTNG_TERM_COLOR` */
		const auto env_val = std::getenv("LTTNG_TERM_COLOR");

		if (env_val) {
			if (std::strcmp(env_val, "always") == 0) {
				when_value = mint::When::Always;
			} else if (std::strcmp(env_val, "never") == 0) {
				when_value = mint::When::Never;
			}
		}
	});

	return when_value;
}

} /* namespace */

std::string mint(const char *const begin, const char *const end)
{
	try {
		return mint::mint(begin, end, when());
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
