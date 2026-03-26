/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APPLICATION_ABI_HPP
#define LTTNG_SESSIOND_UST_APPLICATION_ABI_HPP

#include <common/format.hpp>

#include <cstdint>
#include <string>

namespace lttng {
namespace sessiond {
namespace ust {

enum class application_abi : std::uint8_t {
	ABI_32 = 32,
	ABI_64 = 64,
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::ust::application_abi> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng::sessiond::ust::application_abi abi,
						    FormatContextType& ctx) const
	{
		switch (abi) {
		case lttng::sessiond::ust::application_abi::ABI_32:
			return formatter<std::string>::format("32-bit", ctx);
		case lttng::sessiond::ust::application_abi::ABI_64:
			return formatter<std::string>::format("64-bit", ctx);
		default:
			return formatter<std::string>::format("unknown", ctx);
		}
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_UST_APPLICATION_ABI_HPP */
