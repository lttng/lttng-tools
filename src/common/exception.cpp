/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "exception.hpp"
#include <sstream>
#include <common/error.hpp>

namespace {
std::string format_throw_location(
	const char *file_name, const char *function_name, unsigned int line_number)
{
	std::stringstream location;

	location << "[" << function_name << "()"
		 << " " << file_name << ":" << line_number << "]";

	return location.str();
}
} // namespace

lttng::ctl::error::error(lttng_error_code error_code,
	const char *file_name,
	const char *function_name,
	unsigned int line_number) :
	std::runtime_error(std::string(error_get_str(error_code)) + " " +
		format_throw_location(file_name, function_name, line_number))
{
}

lttng::posix_error::posix_error(const std::string &msg,
	int errno_code,
	const char *file_name,
	const char *function_name,
	unsigned int line_number) :
	std::system_error(errno_code,
		std::generic_category(),
		msg + " " + format_throw_location(file_name, function_name, line_number))
{
}
