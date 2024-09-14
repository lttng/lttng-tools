/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "domain.hpp"

lttng::sessiond::exceptions::channel_not_found_error::channel_not_found_error(
	std::string channel_name_, const lttng::source_location& source_location_) :
	lttng::runtime_error(
		fmt::format("No channel with the given name in domain: channel_name=`{}`",
			    channel_name_),
		source_location_),
	channel_name{ std::move(channel_name_) }
{
}