/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "domain.hpp"

#include <common/defaults.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>

namespace ls = lttng::sessiond::config;

ls::metadata_channel_configuration ls::domain::_make_default_metadata_channel_configuration()
{
	return ls::metadata_channel_configuration(
		DEFAULT_METADATA_NAME,
		ls::channel_configuration::buffer_full_policy_t::DISCARD_EVENT,
		ls::channel_configuration::buffer_consumption_backend_t::MMAP,
		default_get_metadata_subbuf_size(),
		DEFAULT_METADATA_SUBBUF_NUM,
		nonstd::optional<ls::channel_configuration::timer_period_us>(
			DEFAULT_METADATA_SWITCH_TIMER),
		nonstd::optional<ls::channel_configuration::timer_period_us>(
			DEFAULT_METADATA_READ_TIMER));
}

lttng::sessiond::config::exceptions::channel_not_found_error::channel_not_found_error(
	std::string channel_name_, const lttng::source_location& source_location_) :
	lttng::runtime_error(
		fmt::format("No channel with the given name in domain: channel_name=`{}`",
			    channel_name_),
		source_location_),
	channel_name{ std::move(channel_name_) }
{
}
