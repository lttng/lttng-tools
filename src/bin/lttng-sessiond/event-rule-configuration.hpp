/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_EVENT_RULE_CONFIGURATION_HPP
#define LTTNG_SESSIOND_EVENT_RULE_CONFIGURATION_HPP

#include <common/ctl/format.hpp>
#include <common/ctl/memory.hpp>
#include <common/format.hpp>

#include <lttng/event-rule/jul-logging.h>
#include <lttng/event-rule/kernel-kprobe.h>
#include <lttng/event-rule/kernel-syscall.h>
#include <lttng/event-rule/kernel-tracepoint.h>
#include <lttng/event-rule/kernel-uprobe.h>
#include <lttng/event-rule/log4j-logging.h>
#include <lttng/event-rule/log4j2-logging.h>
#include <lttng/event-rule/python-logging.h>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/kernel-probe.h>
#include <lttng/log-level-rule.h>
#include <lttng/userspace-probe.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <string>

namespace lttng {
namespace sessiond {
namespace config {

/*
 * An event rule configuration represents the configuration of a channel or map's
 * event rule at a given point in time. It belongs to a single channel or map.
 */
class event_rule_configuration final {
public:
	using uptr = std::unique_ptr<event_rule_configuration>;

	event_rule_configuration(bool is_enabled, lttng::ctl::event_rule_uptr&& event_rule);

	~event_rule_configuration() = default;
	event_rule_configuration(event_rule_configuration&&) = delete;
	event_rule_configuration(const event_rule_configuration&) = delete;
	event_rule_configuration& operator=(const event_rule_configuration&) = delete;
	event_rule_configuration& operator=(event_rule_configuration&&) = delete;

	void enable() noexcept
	{
		set_enabled(true);
	}

	void disable() noexcept
	{
		set_enabled(false);
	}

	void set_enabled(bool enable) noexcept;

	bool is_enabled;
	const lttng::ctl::event_rule_uptr event_rule;
};

} /* namespace config */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
namespace details {

template <typename OutputItType>
OutputItType format_log_level_rule(OutputItType it, const struct lttng_log_level_rule *llr)
{
	if (!llr) {
		return it;
	}

	const auto type = lttng_log_level_rule_get_type(llr);
	int level = 0;

	switch (type) {
	case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
		(void) lttng_log_level_rule_exactly_get_level(llr, &level);
		return format_to(it, ", log_level=(exactly {})", level);
	case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
		(void) lttng_log_level_rule_at_least_as_severe_as_get_level(llr, &level);
		return format_to(it, ", log_level=(at least as severe as {})", level);
	default:
		return it;
	}
}

template <typename OutputItType>
OutputItType format_kernel_probe_location(OutputItType it,
					  const struct lttng_kernel_probe_location *location)
{
	if (!location) {
		return it;
	}

	switch (lttng_kernel_probe_location_get_type(location)) {
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
	{
		const auto *symbol_name = lttng_kernel_probe_location_symbol_get_name(location);
		uint64_t offset = 0;

		(void) lttng_kernel_probe_location_symbol_get_offset(location, &offset);
		return format_to(it,
				 ", location=(symbol=`{}`, offset={})",
				 symbol_name ? symbol_name : "",
				 offset);
	}
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
	{
		uint64_t address = 0;

		(void) lttng_kernel_probe_location_address_get_address(location, &address);
		return format_to(it, ", location=(address={:#x})", address);
	}
	default:
		return it;
	}
}

template <typename OutputItType>
OutputItType format_userspace_probe_location(OutputItType it,
					     const struct lttng_userspace_probe_location *location)
{
	if (!location) {
		return it;
	}

	switch (lttng_userspace_probe_location_get_type(location)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		const auto *binary =
			lttng_userspace_probe_location_function_get_binary_path(location);
		const auto *function =
			lttng_userspace_probe_location_function_get_function_name(location);

		return format_to(it,
				 ", location=(binary=`{}`, function=`{}`)",
				 binary ? binary : "",
				 function ? function : "");
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		const auto *binary =
			lttng_userspace_probe_location_tracepoint_get_binary_path(location);
		const auto *provider =
			lttng_userspace_probe_location_tracepoint_get_provider_name(location);
		const auto *probe =
			lttng_userspace_probe_location_tracepoint_get_probe_name(location);

		return format_to(it,
				 ", location=(binary=`{}`, provider=`{}`, probe=`{}`)",
				 binary ? binary : "",
				 provider ? provider : "",
				 probe ? probe : "");
	}
	default:
		return it;
	}
}

template <typename OutputItType>
OutputItType format_exclusions(OutputItType it, const struct lttng_event_rule *rule)
{
	unsigned int count = 0;

	if (lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(rule, &count) !=
		    LTTNG_EVENT_RULE_STATUS_OK ||
	    count == 0) {
		return it;
	}

	it = format_to(it, ", exclusions=[");
	for (unsigned int i = 0; i < count; i++) {
		const char *pattern = nullptr;

		if (lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
			    rule, i, &pattern) == LTTNG_EVENT_RULE_STATUS_OK &&
		    pattern) {
			if (i > 0) {
				it = format_to(it, ", ");
			}

			it = format_to(it, "`{}`", pattern);
		}
	}

	return format_to(it, "]");
}

template <typename OutputItType>
OutputItType format_event_rule(OutputItType it, const struct lttng_event_rule *rule)
{
	const char *name_pattern = nullptr;
	const char *filter = nullptr;
	const struct lttng_log_level_rule *llr = nullptr;

	switch (lttng_event_rule_get_type(rule)) {
	case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		(void) lttng_event_rule_user_tracepoint_get_name_pattern(rule, &name_pattern);
		(void) lttng_event_rule_user_tracepoint_get_filter(rule, &filter);
		(void) lttng_event_rule_user_tracepoint_get_log_level_rule(rule, &llr);
		it = format_to(it, ", name_pattern=`{}`", name_pattern ? name_pattern : "*");
		if (filter) {
			it = format_to(it, ", filter=`{}`", filter);
		}
		it = format_log_level_rule(it, llr);
		it = format_exclusions(it, rule);
		break;

	case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		(void) lttng_event_rule_kernel_tracepoint_get_name_pattern(rule, &name_pattern);
		(void) lttng_event_rule_kernel_tracepoint_get_filter(rule, &filter);
		it = format_to(it, ", name_pattern=`{}`", name_pattern ? name_pattern : "*");
		if (filter) {
			it = format_to(it, ", filter=`{}`", filter);
		}
		break;

	case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
	{
		(void) lttng_event_rule_kernel_syscall_get_name_pattern(rule, &name_pattern);
		(void) lttng_event_rule_kernel_syscall_get_filter(rule, &filter);
		const auto emission_site = lttng_event_rule_kernel_syscall_get_emission_site(rule);
		const auto *site_name = [emission_site]() {
			switch (emission_site) {
			case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY:
				return "entry";
			case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT:
				return "exit";
			case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT:
				return "entry+exit";
			default:
				return "unknown";
			}
		}();

		it = format_to(it,
			       ", name_pattern=`{}`, emission_site={}",
			       name_pattern ? name_pattern : "*",
			       site_name);
		if (filter) {
			it = format_to(it, ", filter=`{}`", filter);
		}
		break;
	}

	case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
	{
		const char *event_name = nullptr;
		const struct lttng_kernel_probe_location *location = nullptr;

		(void) lttng_event_rule_kernel_kprobe_get_event_name(rule, &event_name);
		(void) lttng_event_rule_kernel_kprobe_get_location(rule, &location);
		if (event_name) {
			it = format_to(it, ", event_name=`{}`", event_name);
		}
		it = format_kernel_probe_location(it, location);
		break;
	}

	case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
	{
		const char *event_name = nullptr;
		const struct lttng_userspace_probe_location *location = nullptr;

		(void) lttng_event_rule_kernel_uprobe_get_event_name(rule, &event_name);
		(void) lttng_event_rule_kernel_uprobe_get_location(rule, &location);
		if (event_name) {
			it = format_to(it, ", event_name=`{}`", event_name);
		}
		it = format_userspace_probe_location(it, location);
		break;
	}

	case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		(void) lttng_event_rule_jul_logging_get_name_pattern(rule, &name_pattern);
		(void) lttng_event_rule_jul_logging_get_filter(rule, &filter);
		(void) lttng_event_rule_jul_logging_get_log_level_rule(rule, &llr);
		it = format_to(it, ", name_pattern=`{}`", name_pattern ? name_pattern : "*");
		if (filter) {
			it = format_to(it, ", filter=`{}`", filter);
		}
		it = format_log_level_rule(it, llr);
		break;

	case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		(void) lttng_event_rule_log4j_logging_get_name_pattern(rule, &name_pattern);
		(void) lttng_event_rule_log4j_logging_get_filter(rule, &filter);
		(void) lttng_event_rule_log4j_logging_get_log_level_rule(rule, &llr);
		it = format_to(it, ", name_pattern=`{}`", name_pattern ? name_pattern : "*");
		if (filter) {
			it = format_to(it, ", filter=`{}`", filter);
		}
		it = format_log_level_rule(it, llr);
		break;

	case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
		(void) lttng_event_rule_log4j2_logging_get_name_pattern(rule, &name_pattern);
		(void) lttng_event_rule_log4j2_logging_get_filter(rule, &filter);
		(void) lttng_event_rule_log4j2_logging_get_log_level_rule(rule, &llr);
		it = format_to(it, ", name_pattern=`{}`", name_pattern ? name_pattern : "*");
		if (filter) {
			it = format_to(it, ", filter=`{}`", filter);
		}
		it = format_log_level_rule(it, llr);
		break;

	case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		(void) lttng_event_rule_python_logging_get_name_pattern(rule, &name_pattern);
		(void) lttng_event_rule_python_logging_get_filter(rule, &filter);
		(void) lttng_event_rule_python_logging_get_log_level_rule(rule, &llr);
		it = format_to(it, ", name_pattern=`{}`", name_pattern ? name_pattern : "*");
		if (filter) {
			it = format_to(it, ", filter=`{}`", filter);
		}
		it = format_log_level_rule(it, llr);
		break;

	default:
		break;
	}

	return it;
}

} /* namespace details */

template <>
struct formatter<lttng::sessiond::config::event_rule_configuration> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(const lttng::sessiond::config::event_rule_configuration& config,
	       FormatContextType& ctx) const
	{
		const auto *rule = config.event_rule.get();

		auto it = format_to(ctx.out(), "{{enabled={}, rule={}", config.is_enabled, *rule);
		it = details::format_event_rule(it, rule);
		return format_to(it, "}}");
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_EVENT_RULE_CONFIGURATION_HPP */
