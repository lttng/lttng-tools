/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "context-configuration.hpp"
#include "recording-channel-configuration.hpp"
#include "ust-app-channel.hpp"
#include "ust-app-ctx.hpp"
#include "ust-app.hpp"

#include <common/common.hpp>

namespace lsu = lttng::sessiond::ust;
namespace lsc = lttng::sessiond::config;

lsu::app_context::app_context(lsu::app_channel& channel,
			      const lsc::context_configuration& context_config_) :
	context_config(context_config_), _channel(channel)
{
}

lsu::app_context::~app_context()
{
	if (!obj.get()) {
		return;
	}

	lsu::release_object_via_app(_channel.session.app(), *obj.get(), "ctx");
}

/*
 * Determine if the context is redundant for the channel.
 *
 * This is used to avoid sending a context registration to UST. However, it
 * should not be used for filtering context to be added internally by the
 * session daemon.
 *
 * The rationale here is that some contexts are provided implicitly by some
 * channels.
 *
 * LTTNG_UST_ABI_CHAN_PER_CPU:
 *   LTTNG_UST_ABI_CONTEXT_CPU_ID:
 *     The CPU ID is implicitly provided in the packer header.
 */
bool is_context_redundant(const lsc::recording_channel_configuration& chan_config,
			  const lsc::context_configuration& ctx_config)
{
	if (chan_config.buffer_allocation_policy ==
	    lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU) {
		if (ctx_config.context_type == lsc::context_configuration::type::CPU_ID) {
			return true;
		}
	}

	return false;
}
