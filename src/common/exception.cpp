/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "exception.hpp"

#include <common/error.hpp>

#include <lttng/lttng-error.h>

lttng::ctl::error::error(const std::string& msg,
			 lttng_error_code error_code,
			 const lttng::source_location& location) :
	runtime_error(msg, location), _error_code{ error_code }
{
}

lttng::posix_error::posix_error(const std::string& msg,
				unsigned int errno_code,
				const lttng::source_location& location) :
	lttng::runtime_error(msg + ": " + std::system_category().message(errno_code), location)
{
}

lttng::runtime_error::runtime_error(const std::string& msg,
				    const lttng::source_location& location) :
	std::runtime_error(msg), source_location(location)
{
}

lttng::allocation_failure::allocation_failure(const std::string& msg,
					      const lttng::source_location& location) :
	lttng::runtime_error(msg, location)
{
}

lttng::allocation_failure::allocation_failure(const std::string& msg,
					      std::size_t allocation_size_,
					      const lttng::source_location& location) :
	lttng::runtime_error(msg, location), allocation_size(allocation_size_)
{
}

lttng::out_of_range::out_of_range(const std::string& msg, const lttng::source_location& location) :
	lttng::runtime_error(msg, location)
{
}

lttng::unsupported_error::unsupported_error(const std::string& msg,
					    const lttng::source_location& location) :
	lttng::runtime_error(msg, location)
{
}

lttng::communication_error::communication_error(const std::string& msg,
						const lttng::source_location& location) :
	runtime_error(msg, location)
{
}

lttng::protocol_error::protocol_error(const std::string& msg,
				      const lttng::source_location& location) :
	communication_error(msg, location)
{
}

lttng::invalid_argument_error::invalid_argument_error(const std::string& msg,
						      const lttng::source_location& location) :
	runtime_error(msg, location)
{
}
