/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-rule-convert.hpp"

#include <common/ctl/format.hpp>
#include <common/exception.hpp>

using log_level_rule_uptr = std::unique_ptr<
	lttng_log_level_rule,
	lttng::memory::create_deleter_class<lttng_log_level_rule, lttng_log_level_rule_destroy>>;

using EventRuleCreateFunctionType = lttng_event_rule *(*) ();
using EventRuleSetNamePatternFunctionType = lttng_event_rule_status (*)(lttng_event_rule *,
									const char *);
using EventRuleSetLogLevelRuleFunctionType =
	lttng_event_rule_status (*)(lttng_event_rule *, const lttng_log_level_rule *);
using EventRuleSetFilterExpressionFunctionType = lttng_event_rule_status (*)(lttng_event_rule *,
									     const char *);

namespace {
log_level_rule_uptr create_log_level_rule_from_lttng_event(const lttng_event& event)
{
	log_level_rule_uptr rule;
	lttng_log_level_rule_type log_level_rule_type;

	switch (event.loglevel_type) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		return nullptr;
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		rule.reset(lttng_log_level_rule_exactly_create(event.loglevel));
		log_level_rule_type = LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS;
		break;
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		rule.reset(lttng_log_level_rule_at_least_as_severe_as_create(event.loglevel));
		log_level_rule_type = LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY;
		break;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			fmt::format("Invalid log level type: type={}", event.loglevel_type));
	}

	if (!rule) {
		LTTNG_THROW_ERROR(
			fmt::format("Failed to allocate log level rule: rule_type={}, level={}",
				    log_level_rule_type,
				    event.loglevel));
	}

	return rule;
}

template <EventRuleCreateFunctionType EventRuleCreateFunction,
	  EventRuleSetNamePatternFunctionType EventRuleSetNamePatternFunction,
	  EventRuleSetLogLevelRuleFunctionType EventRuleSetLogLevelRuleFunction,
	  EventRuleSetFilterExpressionFunctionType EventRuleSetFilterExpressionFunction>
lttng::event_rule_uptr create_user_or_agent_event_rule_from_lttng_event(
	const lttng_event& event,
	lttng_domain_type domain,
	const log_level_rule_uptr& log_level_rule,
	nonstd::optional<lttng::c_string_view> filter_expression)
{
	lttng::event_rule_uptr rule{ EventRuleCreateFunction() };

	if (!rule) {
		LTTNG_THROW_ERROR(fmt::format("Failed to allocate event rule: domain={}", domain));
	}

	const auto pattern = event.name[0] == '\0' ? "*" : event.name;
	const auto set_pattern_ret = EventRuleSetNamePatternFunction(rule.get(), pattern);
	if (set_pattern_ret != LTTNG_EVENT_RULE_STATUS_OK) {
		LTTNG_THROW_ERROR(fmt::format(
			"Failed to set name pattern on event rule: domain={}, pattern=`{}`",
			domain,
			pattern));
	}

	if (log_level_rule) {
		const auto set_log_level_rule_ret =
			EventRuleSetLogLevelRuleFunction(rule.get(), log_level_rule.get());
		if (set_log_level_rule_ret != LTTNG_EVENT_RULE_STATUS_OK) {
			if (set_log_level_rule_ret == LTTNG_EVENT_RULE_STATUS_INVALID) {
				LTTNG_THROW_CTL("Invalid log level specified for domain",
						LTTNG_ERR_INVALID);
			} else {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to set log level rule on event rule: domain=\"{}\"",
					domain));
			}
		}
	}

	if (filter_expression) {
		const auto set_filter_expression_ret =
			EventRuleSetFilterExpressionFunction(rule.get(), filter_expression->data());
		if (set_filter_expression_ret != LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to set filter expression on event rule: domain={}, filter_expression=`{}`",
				domain,
				*filter_expression));
		}
	}

	return rule;
}

lttng::event_rule_uptr
create_kernel_event_rule_from_lttng_event(const lttng_event& event,
					  nonstd::optional<lttng::c_string_view> filter_expression)
{
	lttng::event_rule_uptr rule;

	switch (event.type) {
	case LTTNG_EVENT_ALL:
		/* Caller should enable all syscalls and all tracepoints explicitly/separately. */
		LTTNG_THROW_UNSUPPORTED_ERROR(
			"'All' instrumentation type is unsupported by the event rule interface");
	case LTTNG_EVENT_TRACEPOINT:
	{
		const auto pattern = event.name[0] == '\0' ? "*" : event.name;
		rule.reset(lttng_event_rule_kernel_tracepoint_create());
		if (!rule) {
			LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
				"Failed to create kernel tracepoint event rule");
		}

		const auto set_pattern_ret =
			lttng_event_rule_kernel_tracepoint_set_name_pattern(rule.get(), pattern);
		if (set_pattern_ret != LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to set name pattern on kernel tracepoint event rule: pattern=`{}`",
				pattern));
		};

		if (filter_expression) {
			const auto set_filter_ret = lttng_event_rule_kernel_tracepoint_set_filter(
				rule.get(), filter_expression->data());
			if (set_filter_ret != LTTNG_EVENT_RULE_STATUS_OK) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to set filter expression on kernel tracepoint event rule: filter_expression=`{}`",
					filter_expression->data()));
			};
		}
		break;
	}
	case LTTNG_EVENT_PROBE:
	case LTTNG_EVENT_FUNCTION:
	{
		lttng::kernel_location_uptr location;

		if (event.attr.probe.symbol_name[0]) {
			/* Specified by name. */
			location.reset(lttng_kernel_probe_location_symbol_create(
				event.attr.probe.symbol_name, event.attr.probe.offset));
		} else {
			/* Specified by address. */
			location.reset(
				lttng_kernel_probe_location_address_create(event.attr.probe.addr));
		}

		if (!location) {
			LTTNG_THROW_ERROR(
				"Failed to create kernel probe location from lttng_event");
		}

		rule.reset(lttng_event_rule_kernel_kprobe_create(location.get()));
		if (!rule) {
			LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
				"Failed to create kernel kprobe event rule");
		}

		const auto set_name_ret =
			lttng_event_rule_kernel_kprobe_set_event_name(rule.get(), event.name);
		if (set_name_ret != LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to set name on kernel tracepoint event rule: name=`{}`",
				event.name));
		}

		break;
	}
	case LTTNG_EVENT_SYSCALL:
	{
		const auto pattern = event.name[0] == '\0' ? "*" : event.name;

		/* Entry + exit is currently the only mode exposed for recording event rules. */
		rule.reset(lttng_event_rule_kernel_syscall_create(
			LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT));
		if (!rule) {
			LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
				"Failed to create kernel syscall event rule");
		}

		const auto set_pattern_ret =
			lttng_event_rule_kernel_syscall_set_name_pattern(rule.get(), pattern);
		if (set_pattern_ret != LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to set name pattern on kernel syscall event rule: pattern=`{}`",
				pattern));
		};

		if (filter_expression) {
			const auto set_filter_ret = lttng_event_rule_kernel_syscall_set_filter(
				rule.get(), filter_expression->data());
			if (set_filter_ret != LTTNG_EVENT_RULE_STATUS_OK) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to set filter expression on kernel syscall event rule: filter_expression=`{}`",
					filter_expression->data()));
			};
		}

		break;
	}
	case LTTNG_EVENT_USERSPACE_PROBE:
	{
		const auto location = lttng_event_get_userspace_probe_location(&event);

		rule.reset(lttng_event_rule_kernel_uprobe_create(location));
		if (!rule) {
			LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
				"Failed to create kernel user space probe event rule");
		}

		const auto set_name_ret =
			lttng_event_rule_kernel_uprobe_set_event_name(rule.get(), event.name);
		if (set_name_ret != LTTNG_EVENT_RULE_STATUS_OK) {
			LTTNG_THROW_ERROR(fmt::format(
				"Failed to set name on kernel uprobe event rule: name=`{}`",
				event.name));
		}

		break;
	}
	default:
		LTTNG_THROW_UNSUPPORTED_ERROR(
			"Unsupported instrumentation type encountered while creating kernel event rule from lttng_event");
	}

	return rule;
}
} /* namespace */

lttng::event_rule_uptr lttng::ctl::create_event_rule_from_lttng_event(
	const lttng_event& event,
	lttng_domain_type domain,
	const nonstd::optional<lttng::c_string_view>& filter_expression,
	const std::vector<lttng::c_string_view>& exclusions)
{
	lttng::event_rule_uptr rule;
	const auto log_level_rule = [&event, domain]() {
		switch (domain) {
		case LTTNG_DOMAIN_UST:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_LOG4J2:
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_PYTHON:
			return create_log_level_rule_from_lttng_event(event);
		default:
			return log_level_rule_uptr();
		}
	}();

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		rule = create_kernel_event_rule_from_lttng_event(event, filter_expression);
		break;
	case LTTNG_DOMAIN_UST:
		rule = create_user_or_agent_event_rule_from_lttng_event<
			lttng_event_rule_user_tracepoint_create,
			lttng_event_rule_user_tracepoint_set_name_pattern,
			lttng_event_rule_user_tracepoint_set_log_level_rule,
			lttng_event_rule_user_tracepoint_set_filter>(
			event, domain, log_level_rule, filter_expression);
		break;
	case LTTNG_DOMAIN_LOG4J:
		rule = create_user_or_agent_event_rule_from_lttng_event<
			lttng_event_rule_log4j_logging_create,
			lttng_event_rule_log4j_logging_set_name_pattern,
			lttng_event_rule_log4j_logging_set_log_level_rule,
			lttng_event_rule_log4j_logging_set_filter>(
			event, domain, log_level_rule, filter_expression);
		break;
	case LTTNG_DOMAIN_LOG4J2:
		rule = create_user_or_agent_event_rule_from_lttng_event<
			lttng_event_rule_log4j2_logging_create,
			lttng_event_rule_log4j2_logging_set_name_pattern,
			lttng_event_rule_log4j2_logging_set_log_level_rule,
			lttng_event_rule_log4j2_logging_set_filter>(
			event, domain, log_level_rule, filter_expression);
		break;
	case LTTNG_DOMAIN_JUL:
		rule = create_user_or_agent_event_rule_from_lttng_event<
			lttng_event_rule_jul_logging_create,
			lttng_event_rule_jul_logging_set_name_pattern,
			lttng_event_rule_jul_logging_set_log_level_rule,
			lttng_event_rule_jul_logging_set_filter>(
			event, domain, log_level_rule, filter_expression);
		break;
	case LTTNG_DOMAIN_PYTHON:
		rule = create_user_or_agent_event_rule_from_lttng_event<
			lttng_event_rule_python_logging_create,
			lttng_event_rule_python_logging_set_name_pattern,
			lttng_event_rule_python_logging_set_log_level_rule,
			lttng_event_rule_python_logging_set_filter>(
			event, domain, log_level_rule, filter_expression);
		break;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Invalid domain specified during event-rule creation: domain={}", domain));
	}

	if (!exclusions.empty()) {
		if (domain != LTTNG_DOMAIN_UST) {
			LTTNG_THROW_UNSUPPORTED_ERROR(
				"Pattern exclusions are only supported by the user space domain");
		}

		for (const auto& exclusion : exclusions) {
			const auto set_exclusions_ret =
				lttng_event_rule_user_tracepoint_add_name_pattern_exclusion(
					rule.get(), exclusion.data());

			if (set_exclusions_ret != LTTNG_EVENT_RULE_STATUS_OK) {
				LTTNG_THROW_ERROR(fmt::format(
					"Failed to add name pattern exclusion to event rule: pattern=`{}`",
					exclusion));
			}
		}
	}

	return rule;
}
