/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-channel-from-config.hpp"
#include "recording-channel-configuration.hpp"

#include <common/exception.hpp>
#include <common/macros.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/optional.hpp>

#include <lttng/channel-internal.hpp>
#include <lttng/channel.h>

namespace lsc = lttng::sessiond::config;

lttng::ctl::lttng_channel_uptr
lttng::sessiond::make_lttng_channel(const lsc::recording_channel_configuration& channel_config)
{
	auto attr = lttng::make_unique_wrapper<lttng_channel, lttng_channel_destroy>(
		lttng_channel_create_internal());
	if (!attr) {
		LTTNG_THROW_POSIX("Failed to allocate lttng_channel", ENOMEM);
	}

	if (lttng_strncpy(attr->name, channel_config.name.c_str(), sizeof(attr->name))) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Channel name too long");
	}

	attr->enabled = channel_config.is_enabled ? 1 : 0;

	attr->attr.overwrite = channel_config.buffer_full_policy ==
			lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET ?
		1 :
		0;
	attr->attr.subbuf_size = channel_config.subbuffer_size_bytes;
	attr->attr.num_subbuf = channel_config.subbuffer_count;
	attr->attr.switch_timer_interval = channel_config.switch_timer_period_us.value_or(0);
	attr->attr.read_timer_interval = channel_config.read_timer_period_us.value_or(0);
	attr->attr.output = channel_config.buffer_consumption_backend ==
			lsc::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_EVENT_MMAP :
		LTTNG_EVENT_SPLICE;

	if (channel_config.live_timer_period_us) {
		attr->attr.live_timer_interval = *channel_config.live_timer_period_us;
	}

	if (channel_config.monitor_timer_period_us) {
		lttng_channel_set_monitor_timer_interval(attr.get(),
							 *channel_config.monitor_timer_period_us);
	}

	if (channel_config.trace_file_size_limit_bytes) {
		attr->attr.tracefile_size = *channel_config.trace_file_size_limit_bytes;
	}

	if (channel_config.trace_file_count_limit) {
		attr->attr.tracefile_count = *channel_config.trace_file_count_limit;
	}

	/* Populate extended attributes. */
	auto *extended = reinterpret_cast<lttng_channel_extended *>(attr->attr.extended.ptr);

	switch (channel_config.consumption_blocking_policy_.mode_) {
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::NONE:
		extended->blocking_timeout = 0;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::UNBOUNDED:
		extended->blocking_timeout = -1;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::TIMED:
		extended->blocking_timeout =
			*channel_config.consumption_blocking_policy_.timeout_us;
		break;
	}

	extended->allocation_policy = channel_config.buffer_allocation_policy ==
			lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU ?
		LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU :
		LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL;

	extended->preallocation_policy = channel_config.buffer_preallocation_policy ==
			lsc::recording_channel_configuration::buffer_preallocation_policy_t::
				PREALLOCATE ?
		LTTNG_CHANNEL_PREALLOCATION_POLICY_PREALLOCATE :
		LTTNG_CHANNEL_PREALLOCATION_POLICY_ON_DEMAND;

	if (channel_config.watchdog_timer_period_us) {
		LTTNG_OPTIONAL_SET(&extended->watchdog_timer_interval,
				   *channel_config.watchdog_timer_period_us);
	}

	if (channel_config.automatic_memory_reclamation_maximal_age) {
		LTTNG_OPTIONAL_SET(
			&extended->automatic_memory_reclamation_maximal_age_us,
			static_cast<std::uint64_t>(
				channel_config.automatic_memory_reclamation_maximal_age->count()));
	}

	return attr;
}
