/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LIB_CONSUMER_CONSUMER_TYPE_HPP
#define LIB_CONSUMER_CONSUMER_TYPE_HPP

#include <common/format.hpp>

#include <cstdint>

enum lttng_consumer_type : std::uint8_t {
	LTTNG_CONSUMER_UNKNOWN = 0,
	LTTNG_CONSUMER_KERNEL,
	LTTNG_CONSUMER64_UST,
	LTTNG_CONSUMER32_UST,
};

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng_consumer_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_consumer_type consumer_type,
						    FormatContextType& ctx) const
	{
		const char *name;

		switch (consumer_type) {
		case LTTNG_CONSUMER_KERNEL:
			name = "kernel consumer";
			break;
		case LTTNG_CONSUMER64_UST:
			name = "64-bit user space consumer";
			break;
		case LTTNG_CONSUMER32_UST:
			name = "32-bit user space consumer";
			break;
		case LTTNG_CONSUMER_UNKNOWN:
			name = "unknown consumer";
			break;
		default:
			std::abort();
		}

		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */

#endif /* LIB_CONSUMER_CONSUMER_TYPE_HPP */