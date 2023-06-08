/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef LTTNG_FORMAT_H
#define LTTNG_FORMAT_H

#include <common/macros.hpp>

#include <cxxabi.h>
#include <string>
#include <utility>

DIAGNOSTIC_PUSH
DIAGNOSTIC_IGNORE_SUGGEST_ATTRIBUTE_FORMAT
DIAGNOSTIC_IGNORE_DUPLICATED_BRANCHES
#define FMT_HEADER_ONLY
#include <vendor/fmt/core.h>
DIAGNOSTIC_POP

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<std::type_info> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const std::type_info& type_info,
						    FormatContextType& ctx)
	{
		int status;
		auto demangled_name =
			abi::__cxa_demangle(type_info.name(), nullptr, nullptr, &status);
		auto it = status == 0 ? formatter<std::string>::format(demangled_name, ctx) :
					formatter<std::string>::format(type_info.name(), ctx);

		free(demangled_name);
		return it;
	}
};
} /* namespace fmt */

namespace lttng {
template <typename... FormattingArguments>
std::string format(FormattingArguments&&...args)
{
	try {
		return fmt::format(std::forward<FormattingArguments>(args)...);
	} catch (const fmt::format_error& ex) {
		return std::string("Failed to format string: ") += ex.what();
	}
}
} /* namespace lttng */

#endif /* LTTNG_FORMAT_H */
