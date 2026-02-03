/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_AGENT_DOMAIN_HPP
#define LTTNG_SESSIOND_AGENT_DOMAIN_HPP

#include "event-rule-configuration.hpp"

#include <common/container-wrapper.hpp>
#include <common/domain.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>

#include <functional>
#include <memory>
#include <unordered_map>

namespace lttng {
namespace sessiond {

/*
 * An agent domain holds the event rule configurations for agent domains
 * (JUL, Log4j, Log4j2, Python) within a recording session. Unlike regular
 * domains (user space, kernel), agent domains do not have channels - event
 * rules are stored directly in the domain.
 */
class agent_domain final {
public:
	explicit agent_domain(lttng::domain_class domain_class) : domain_class_(domain_class)
	{
	}

	~agent_domain() = default;
	agent_domain(agent_domain&& other) noexcept :
		domain_class_(other.domain_class_), _event_rules(std::move(other._event_rules))
	{
	}

	agent_domain(const agent_domain&) = delete;
	agent_domain& operator=(const agent_domain&) = delete;
	agent_domain& operator=(agent_domain&&) = delete;

	/* Add an event rule configuration by constructing it in place. */
	template <typename... Args>
	void add_event_rule_configuration(Args&&...args)
	{
		auto config =
			lttng::make_unique<event_rule_configuration>(std::forward<Args>(args)...);

		_event_rules.emplace(std::cref(*config->event_rule), std::move(config));
	}

	/* Lookup by event rule. Throws if not found. */
	event_rule_configuration&
	get_event_rule_configuration(const lttng_event_rule& matching_event_rule_to_lookup);
	const event_rule_configuration&
	get_event_rule_configuration(const lttng_event_rule& matching_event_rule_to_lookup) const;

	/* Check if an event rule configuration exists. */
	bool has_event_rule_configuration(
		const lttng_event_rule& matching_event_rule_to_lookup) const noexcept;

	using event_rules_view = lttng::utils::dereferenced_mapped_values_view<
		std::unordered_map<std::reference_wrapper<const lttng_event_rule>,
				   event_rule_configuration::uptr,
				   std::hash<std::reference_wrapper<const lttng_event_rule>>,
				   lttng_event_rule_ref_equal>,
		event_rule_configuration>;
	using const_event_rules_view = lttng::utils::dereferenced_mapped_values_view<
		const std::unordered_map<std::reference_wrapper<const lttng_event_rule>,
					 event_rule_configuration::uptr,
					 std::hash<std::reference_wrapper<const lttng_event_rule>>,
					 lttng_event_rule_ref_equal>,
		const event_rule_configuration>;

	event_rules_view event_rules() noexcept
	{
		return event_rules_view(_event_rules);
	}

	const_event_rules_view event_rules() const noexcept
	{
		return const_event_rules_view(_event_rules);
	}

	const lttng::domain_class domain_class_;

private:
	std::unordered_map<std::reference_wrapper<const lttng_event_rule>,
			   event_rule_configuration::uptr,
			   std::hash<std::reference_wrapper<const lttng_event_rule>>,
			   lttng_event_rule_ref_equal>
		_event_rules;
};

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_AGENT_DOMAIN_HPP */
