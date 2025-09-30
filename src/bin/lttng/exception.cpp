/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "exception.hpp"

#include <common/format.hpp>
#include <common/utils.hpp>

lttng::cli::no_default_session_error::no_default_session_error(
	const lttng::source_location& location) :
	runtime_error(fmt::format("No default session found in `{}/.lttngrc`",
				  utils_get_home_dir() ?: "LTTNG_HOME"),
		      location)
{
}

lttng::cli::invalid_usage_error::invalid_usage_error(const std::string& message,
						     const lttng::source_location& location) :
	runtime_error(message, location)
{
}

lttng::cli::show_help_failure::show_help_failure(const char *command_name,
						 const lttng::source_location& location) :
	runtime_error(lttng::format("Cannot show --help for `lttng-{}`", command_name), location)
{
}
