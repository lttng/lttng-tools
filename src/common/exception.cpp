/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "exception.hpp"

#include <common/error.hpp>

#include <sstream>

namespace {
std::string
format_throw_location(const char *file_name, const char *function_name, unsigned int line_number)
{
	std::stringstream location;

	location << "[" << function_name << "()"
		 << " " << file_name << ":" << line_number << "]";

	return location.str();
}
} /* namespace */

lttng::ctl::error::error(const std::string& msg,
			 lttng_error_code error_code,
			 const char *file_name,
			 const char *function_name,
			 unsigned int line_number) :
	runtime_error(msg + ": " + std::string(error_get_str(error_code)),
		      file_name,
		      function_name,
		      line_number),
	_error_code{ error_code }
{
}

lttng::posix_error::posix_error(const std::string& msg,
				int errno_code,
				const char *file_name,
				const char *function_name,
				unsigned int line_number) :
	std::system_error(errno_code,
			  std::generic_category(),
			  msg + " " + format_throw_location(file_name, function_name, line_number))
{
}

lttng::runtime_error::runtime_error(const std::string& msg,
				    const char *file_name,
				    const char *function_name,
				    unsigned int line_number) :
	std::runtime_error(msg + " " + format_throw_location(file_name, function_name, line_number))
{
}

lttng::unsupported_error::unsupported_error(const std::string& msg,
					    const char *file_name,
					    const char *function_name,
					    unsigned int line_number) :
	std::runtime_error(msg + " " + format_throw_location(file_name, function_name, line_number))
{
}

lttng::communication_error::communication_error(const std::string& msg,
						const char *file_name,
						const char *function_name,
						unsigned int line_number) :
	runtime_error(msg, file_name, function_name, line_number)
{
}

lttng::protocol_error::protocol_error(const std::string& msg,
				      const char *file_name,
				      const char *function_name,
				      unsigned int line_number) :
	communication_error(msg, file_name, function_name, line_number)
{
}

lttng::invalid_argument_error::invalid_argument_error(const std::string& msg,
						      const char *file_name,
						      const char *function_name,
						      unsigned int line_number) :
	runtime_error(msg, file_name, function_name, line_number)
{
}
