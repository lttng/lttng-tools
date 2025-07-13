/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "domain.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>

lttng::sessiond::exceptions::channel_not_found_error::channel_not_found_error(
	std::string channel_name_, const lttng::source_location& source_location_) :
	lttng::runtime_error(
		fmt::format("No channel with the given name in domain: channel_name=`{}`",
			    channel_name_),
		source_location_),
	channel_name{ std::move(channel_name_) }
{
}

lttng::sessiond::domain_class
lttng::sessiond::get_domain_class_from_lttng_domain_type(enum lttng_domain_type domain_type)
{
	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
		return lttng::sessiond::domain_class::KERNEL_SPACE;
	case LTTNG_DOMAIN_UST:
		return lttng::sessiond::domain_class::USER_SPACE;
	case LTTNG_DOMAIN_JUL:
		return lttng::sessiond::domain_class::JAVA_UTIL_LOGGING;
	case LTTNG_DOMAIN_LOG4J:
		return lttng::sessiond::domain_class::LOG4J;
	case LTTNG_DOMAIN_PYTHON:
		return lttng::sessiond::domain_class::PYTHON_LOGGING;
	case LTTNG_DOMAIN_LOG4J2:
		return lttng::sessiond::domain_class::LOG4J2;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"No suitable conversion exists from lttng_domain_type enum to lttng::sessiond::domain_class");
	}
}