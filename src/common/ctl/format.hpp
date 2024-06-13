/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_CTL_FORMAT_H
#define LTTNG_COMMON_CTL_FORMAT_H

#include <common/format.hpp>

#include <lttng/lttng.h>

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng_buffer_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_buffer_type buffer_type,
						    FormatContextType& ctx)
	{
		auto name = "unknown";

		switch (buffer_type) {
		case LTTNG_BUFFER_PER_PID:
			name = "per-pid";
			break;
		case LTTNG_BUFFER_PER_UID:
			name = "per-uid";
			break;
		case LTTNG_BUFFER_GLOBAL:
			name = "global";
			break;
		}

		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */

#endif /* LTTNG_COMMON_CTL_FORMAT_H */