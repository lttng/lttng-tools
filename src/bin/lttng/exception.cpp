/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "exception.hpp"

#include <common/format.hpp>
#include <common/utils.hpp>

#include <sstream>

lttng::cli::no_default_session_error::no_default_session_error(
	const lttng::source_location& location) :
	runtime_error(fmt::format("No default session found in `{}/.lttngrc`",
				  utils_get_home_dir() ?: "LTTNG_HOME"),
		      location)
{
}
