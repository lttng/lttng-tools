/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "lttng/domain.h"

#include <common/ctl/domain.hpp>
#include <common/exception.hpp>

lttng_domain_type
lttng::ctl::get_lttng_domain_type_from_domain_class(lttng::domain_class domain_class)
{
	switch (domain_class) {
	case lttng::domain_class::KERNEL_SPACE:
		return LTTNG_DOMAIN_KERNEL;
	case lttng::domain_class::USER_SPACE:
		return LTTNG_DOMAIN_UST;
	case lttng::domain_class::JAVA_UTIL_LOGGING:
		return LTTNG_DOMAIN_JUL;
	case lttng::domain_class::PYTHON_LOGGING:
		return LTTNG_DOMAIN_PYTHON;
	case lttng::domain_class::LOG4J:
		return LTTNG_DOMAIN_LOG4J;
	case lttng::domain_class::LOG4J2:
		return LTTNG_DOMAIN_LOG4J2;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"No suitable conversion exists from lttng_domain_type enum to lttng::domain_class");
	}
}
