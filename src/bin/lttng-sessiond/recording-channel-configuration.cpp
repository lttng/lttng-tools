/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "recording-channel-configuration.hpp"

#include <common/ctl/format.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>

namespace ls = lttng::sessiond;

ls::exceptions::event_rule_configuration_not_found_error::event_rule_configuration_not_found_error(
	const lttng_event_rule& event_rule_, const lttng::source_location& source_location_) :
	lttng::runtime_error(
		fmt::format("No matching event-rule in channel configuration: event_rule=`{}`",
			    event_rule_),
		source_location_)
{
}

ls::recording_channel_configuration::recording_channel_configuration(
	bool is_enabled_,
	std::string name_,
	buffer_full_policy_t buffer_full_policy_,
	buffer_consumption_backend_t buffer_consumption_backend_,
	buffer_allocation_policy_t buffer_allocation_policy_,
	buffer_preallocation_policy_t buffer_preallocation_policy_,
	std::uint64_t subbuffer_size_bytes_,
	unsigned int subbuffer_count_,
	const nonstd::optional<timer_period_us>& switch_timer_period_us_,
	const nonstd::optional<timer_period_us>& read_timer_period_us_,
	const nonstd::optional<timer_period_us>& live_timer_period_us_,
	const nonstd::optional<timer_period_us>& monitor_timer_period_us_,
	const nonstd::optional<timer_period_us>& watchdog_timer_period_us_,
	const nonstd::optional<std::chrono::microseconds>& automatic_memory_reclamation_maximal_age_,
	consumption_blocking_policy blocking_policy,
	const nonstd::optional<std::uint64_t>& trace_file_size_limit_bytes_,
	const nonstd::optional<unsigned int>& trace_file_count_limit_) :
	name(std::move(name_)),
	buffer_full_policy(buffer_full_policy_),
	buffer_consumption_backend(buffer_consumption_backend_),
	buffer_allocation_policy(buffer_allocation_policy_),
	buffer_preallocation_policy(buffer_preallocation_policy_),
	subbuffer_size_bytes(subbuffer_size_bytes_),
	subbuffer_count(subbuffer_count_),
	switch_timer_period_us(switch_timer_period_us_),
	read_timer_period_us(read_timer_period_us_),
	live_timer_period_us(live_timer_period_us_),
	monitor_timer_period_us(monitor_timer_period_us_),
	watchdog_timer_period_us(watchdog_timer_period_us_),
	automatic_memory_reclamation_maximal_age(automatic_memory_reclamation_maximal_age_),
	consumption_blocking_policy_(std::move(blocking_policy)),
	trace_file_size_limit_bytes(trace_file_size_limit_bytes_),
	trace_file_count_limit(trace_file_count_limit_),
	is_enabled(is_enabled_)
{
}

ls::recording_channel_configuration::consumption_blocking_policy::consumption_blocking_policy(
	ls::recording_channel_configuration::consumption_blocking_policy::mode policy_mode,
	const nonstd::optional<timer_period_us>& blocking_timeout_us) :
	mode_(policy_mode), timeout_us(blocking_timeout_us)
{
	if (blocking_timeout_us.has_value() !=
	    (policy_mode ==
	     ls::recording_channel_configuration::consumption_blocking_policy::mode::TIMED)) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Invalid timeout argument specified for consumption blocking policy: policy_mode={}, timeout={}",
			mode_,
			timeout_us));
	}
}

void ls::recording_channel_configuration::set_enabled(bool enable) noexcept
{
	is_enabled = enable;
}

const ls::event_rule_configuration&
ls::recording_channel_configuration::get_event_rule_configuration(
	const lttng_event_rule& matching_event_rule_to_lookup) const
{
	/* NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) */
	return const_cast<recording_channel_configuration *>(this)->get_event_rule_configuration(
		matching_event_rule_to_lookup);
}

ls::event_rule_configuration& ls::recording_channel_configuration::get_event_rule_configuration(
	const lttng_event_rule& matching_event_rule_to_lookup)
{
	const auto it = event_rules.find(std::ref(matching_event_rule_to_lookup));
	if (it == event_rules.end()) {
		LTTNG_THROW_EVENT_RULE_CONFIGURATION_NOT_FOUND_ERROR(matching_event_rule_to_lookup);
	}

	return *(it->second);
}
