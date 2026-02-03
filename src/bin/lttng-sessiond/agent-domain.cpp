/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "agent-domain.hpp"
#include "recording-channel-configuration.hpp"

namespace ls = lttng::sessiond;

ls::event_rule_configuration& ls::agent_domain::get_event_rule_configuration(
	const lttng_event_rule& matching_event_rule_to_lookup)
{
	const auto it = _event_rules.find(std::ref(matching_event_rule_to_lookup));
	if (it == _event_rules.end()) {
		LTTNG_THROW_EVENT_RULE_CONFIGURATION_NOT_FOUND_ERROR(matching_event_rule_to_lookup);
	}

	return *(it->second);
}

const ls::event_rule_configuration& ls::agent_domain::get_event_rule_configuration(
	const lttng_event_rule& matching_event_rule_to_lookup) const
{
	/* NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) */
	return const_cast<agent_domain *>(this)->get_event_rule_configuration(
		matching_event_rule_to_lookup);
}

bool ls::agent_domain::has_event_rule_configuration(
	const lttng_event_rule& matching_event_rule_to_lookup) const noexcept
{
	return _event_rules.find(std::ref(matching_event_rule_to_lookup)) != _event_rules.end();
}
