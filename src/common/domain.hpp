/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_DOMAIN_HPP
#define LTTNG_DOMAIN_HPP

#include <common/format.hpp>

#include <lttng/lttng.h>

namespace lttng {

enum class domain_class {
	USER_SPACE,
	KERNEL_SPACE,
	LOG4J,
	LOG4J2,
	JAVA_UTIL_LOGGING,
	PYTHON_LOGGING,
};

domain_class get_domain_class_from_lttng_domain_type(lttng_domain_type domain_type);

/* Returns true for agent domains (LOG4J, LOG4J2, JAVA_UTIL_LOGGING, PYTHON_LOGGING). */
inline bool is_agent_domain(domain_class domain) noexcept
{
	switch (domain) {
	case domain_class::LOG4J:
	case domain_class::LOG4J2:
	case domain_class::JAVA_UTIL_LOGGING:
	case domain_class::PYTHON_LOGGING:
		return true;
	case domain_class::USER_SPACE:
	case domain_class::KERNEL_SPACE:
		return false;
	}

	return false;
}
} /* namespace lttng */

/*
 * Specialize fmt::formatter for domain_class.
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::domain_class> : formatter<std::string> {
	/* Format function to convert enum to string. */
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng::domain_class domain,
						    FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (domain) {
		case lttng::domain_class::USER_SPACE:
			name = "USER_SPACE";
			break;
		case lttng::domain_class::KERNEL_SPACE:
			name = "KERNEL_SPACE";
			break;
		case lttng::domain_class::LOG4J:
			name = "LOG4J";
			break;
		case lttng::domain_class::LOG4J2:
			name = "LOG4J2";
			break;
		case lttng::domain_class::JAVA_UTIL_LOGGING:
			name = "JAVA_UTIL_LOGGING";
			break;
		case lttng::domain_class::PYTHON_LOGGING:
			name = "PYTHON_LOGGING";
			break;
		}

		/* Write the string representation to the format context output iterator. */
		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */
#endif
