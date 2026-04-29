/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_CTL_FORMAT_H
#define LTTNG_COMMON_CTL_FORMAT_H

#include "lttng/lttng-error.h"

#include <common/format.hpp>

#include <lttng/lttng.h>

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng_buffer_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_buffer_type buffer_type,
						    FormatContextType& ctx) const
	{
		auto name = "unknown";

		switch (buffer_type) {
		case LTTNG_BUFFER_PER_PID:
			name = "per-pid";
			break;
		case LTTNG_BUFFER_PER_UID:
			name = "per-uid";
			break;
		case LTTNG_BUFFER_GLOBAL:
			name = "global";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng_domain_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_domain_type domain_type,
						    FormatContextType& ctx) const
	{
		auto name = "unknown";

		switch (domain_type) {
		case LTTNG_DOMAIN_NONE:
			name = "none";
			break;
		case LTTNG_DOMAIN_KERNEL:
			name = "kernel";
			break;
		case LTTNG_DOMAIN_UST:
			name = "user space";
			break;
		case LTTNG_DOMAIN_JUL:
			name = "java.util.logging (JUL)";
			break;
		case LTTNG_DOMAIN_LOG4J:
			name = "log4j";
			break;
		case LTTNG_DOMAIN_LOG4J2:
			name = "log4j2";
			break;
		case LTTNG_DOMAIN_PYTHON:
			name = "Python logging";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng_loglevel_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_loglevel_type loglevel_type,
						    FormatContextType& ctx) const
	{
		auto name = "unknown";

		switch (loglevel_type) {
		case LTTNG_EVENT_LOGLEVEL_ALL:
			name = "all";
			break;
		case LTTNG_EVENT_LOGLEVEL_RANGE:
			name = "range";
			break;
		case LTTNG_EVENT_LOGLEVEL_SINGLE:
			name = "single";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng_event_rule_kernel_syscall_emission_site> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng_event_rule_kernel_syscall_emission_site emission_site,
	       FormatContextType& ctx) const
	{
		const char *name;

		switch (emission_site) {
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY_EXIT:
			name = "ENTRY_EXIT";
			break;
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_ENTRY:
			name = "ENTRY";
			break;
		case LTTNG_EVENT_RULE_KERNEL_SYSCALL_EMISSION_SITE_EXIT:
			name = "EXIT";
			break;
		default:
			name = "UNKNOWN";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng_log_level_rule_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_log_level_rule_type rule_type,
						    FormatContextType& ctx) const
	{
		auto name = "unknown";

		switch (rule_type) {
		case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
			name = "exactly";
			break;
		case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
			name = "\"at least as severe as\"";
			break;
		case LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN:
			break;
		}

		return format_to(ctx.out(), name);
	}
};

namespace details {
template <typename FormatContextIteratorType>
FormatContextIteratorType format_event_expr(const lttng_event_expr *event_expr,
					    FormatContextIteratorType out)
{
	if (!event_expr) {
		return format_to(out, "(none)");
	}

	switch (lttng_event_expr_get_type(event_expr)) {
	case LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD:
		return format_to(
			out, "{}", lttng_event_expr_event_payload_field_get_name(event_expr));
	case LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD:
		return format_to(out,
				 "$ctx.{}",
				 lttng_event_expr_channel_context_field_get_name(event_expr));
	case LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD:
		return format_to(
			out,
			"$app.{}:{}",
			lttng_event_expr_app_specific_context_field_get_provider_name(event_expr),
			lttng_event_expr_app_specific_context_field_get_type_name(event_expr));
	case LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT:
	{
		const auto *parent =
			lttng_event_expr_array_field_element_get_parent_expr(event_expr);
		unsigned int index = 0;
		(void) lttng_event_expr_array_field_element_get_index(event_expr, &index);

		out = format_event_expr(parent, out);
		return format_to(out, "[{}]", index);
	}
	default:
		return format_to(out, "(unknown)");
	}
}

template <typename FormatContextIteratorType>
FormatContextIteratorType format_log_level_rule(const lttng_log_level_rule *rule,
						FormatContextIteratorType out)
{
	if (!rule) {
		return format_to(out, "(none)");
	}

	const auto type = lttng_log_level_rule_get_type(rule);
	int level = 0;

	switch (type) {
	case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
		(void) lttng_log_level_rule_exactly_get_level(rule, &level);
		return format_to(out, "{{type=EXACTLY, level={}}}", level);
	case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
		(void) lttng_log_level_rule_at_least_as_severe_as_get_level(rule, &level);
		return format_to(out, "{{type=AT_LEAST_AS_SEVERE_AS, level={}}}", level);
	case LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN:
	default:
		return format_to(out, "{{type=UNKNOWN}}");
	}
}

template <typename FormatContextIteratorType>
FormatContextIteratorType format_kernel_probe_location(const lttng_kernel_probe_location *location,
						       FormatContextIteratorType out)
{
	if (!location) {
		return format_to(out, "(none)");
	}

	const auto type = lttng_kernel_probe_location_get_type(location);

	switch (type) {
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_SYMBOL_OFFSET:
	{
		const char *name = lttng_kernel_probe_location_symbol_get_name(location);
		std::uint64_t offset = 0;
		(void) lttng_kernel_probe_location_symbol_get_offset(location, &offset);
		return format_to(out,
				 "{{type=SYMBOL_OFFSET, symbol=`{}`, offset={}}}",
				 name ? name : "",
				 offset);
	}
	case LTTNG_KERNEL_PROBE_LOCATION_TYPE_ADDRESS:
	{
		std::uint64_t address = 0;
		(void) lttng_kernel_probe_location_address_get_address(location, &address);
		return format_to(out, "{{type=ADDRESS, address={:#x}}}", address);
	}
	default:
		return format_to(out, "{{type=UNKNOWN}}");
	}
}

template <typename FormatContextIteratorType>
FormatContextIteratorType
format_userspace_probe_location(const lttng_userspace_probe_location *location,
				FormatContextIteratorType out)
{
	if (!location) {
		return format_to(out, "(none)");
	}

	const auto type = lttng_userspace_probe_location_get_type(location);

	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		const char *binary_path =
			lttng_userspace_probe_location_function_get_binary_path(location);
		const char *function_name =
			lttng_userspace_probe_location_function_get_function_name(location);
		return format_to(out,
				 "{{type=FUNCTION, binary_path=`{}`, function_name=`{}`}}",
				 binary_path ? binary_path : "",
				 function_name ? function_name : "");
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		const char *binary_path =
			lttng_userspace_probe_location_tracepoint_get_binary_path(location);
		const char *provider_name =
			lttng_userspace_probe_location_tracepoint_get_provider_name(location);
		const char *probe_name =
			lttng_userspace_probe_location_tracepoint_get_probe_name(location);
		return format_to(
			out,
			"{{type=TRACEPOINT, binary_path=`{}`, provider_name=`{}`, probe_name=`{}`}}",
			binary_path ? binary_path : "",
			provider_name ? provider_name : "",
			probe_name ? probe_name : "");
	}
	default:
		return format_to(out, "{{type=UNKNOWN}}");
	}
}
} /* namespace details */

template <>
struct formatter<lttng_event_rule> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const lttng_event_rule& rule,
						    FormatContextType& ctx) const
	{
		const auto rule_type = lttng_event_rule_get_type(&rule);

		switch (rule_type) {
		case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
		{
			const char *name_pattern = nullptr;
			const char *filter = nullptr;

			(void) lttng_event_rule_kernel_tracepoint_get_name_pattern(&rule,
										   &name_pattern);
			(void) lttng_event_rule_kernel_tracepoint_get_filter(&rule, &filter);

			return format_to(
				ctx.out(),
				"{{type=KERNEL_TRACEPOINT, name_pattern=`{}`, filter=`{}`}}",
				name_pattern ? name_pattern : "",
				filter ? filter : "");
		}
		case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
		{
			const char *name_pattern = nullptr;
			const char *filter = nullptr;

			(void) lttng_event_rule_kernel_syscall_get_name_pattern(&rule,
										&name_pattern);
			(void) lttng_event_rule_kernel_syscall_get_filter(&rule, &filter);

			return format_to(
				ctx.out(),
				"{{type=KERNEL_SYSCALL, name_pattern=`{}`, filter=`{}`, emission_site={}}}",
				name_pattern ? name_pattern : "",
				filter ? filter : "",
				lttng_event_rule_kernel_syscall_get_emission_site(&rule));
		}
		case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
		{
			const char *event_name = nullptr;
			const lttng_kernel_probe_location *location = nullptr;

			(void) lttng_event_rule_kernel_kprobe_get_event_name(&rule, &event_name);
			(void) lttng_event_rule_kernel_kprobe_get_location(&rule, &location);

			auto out = format_to(ctx.out(),
					     "{{type=KERNEL_KPROBE, event_name=`{}`, location=",
					     event_name ? event_name : "");
			out = details::format_kernel_probe_location(location, out);
			return format_to(out, "}}");
		}
		case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
		{
			const char *event_name = nullptr;
			const lttng_userspace_probe_location *location = nullptr;

			(void) lttng_event_rule_kernel_uprobe_get_event_name(&rule, &event_name);
			(void) lttng_event_rule_kernel_uprobe_get_location(&rule, &location);

			auto out = format_to(ctx.out(),
					     "{{type=KERNEL_UPROBE, event_name=`{}`, location=",
					     event_name ? event_name : "");
			out = details::format_userspace_probe_location(location, out);
			return format_to(out, "}}");
		}
		case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
		{
			const char *name_pattern = nullptr;
			const char *filter = nullptr;
			const lttng_log_level_rule *log_level_rule = nullptr;
			unsigned int exclusion_count = 0;

			(void) lttng_event_rule_user_tracepoint_get_name_pattern(&rule,
										 &name_pattern);
			(void) lttng_event_rule_user_tracepoint_get_filter(&rule, &filter);
			(void) lttng_event_rule_user_tracepoint_get_log_level_rule(&rule,
										   &log_level_rule);
			(void) lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_count(
				&rule, &exclusion_count);

			auto out = format_to(
				ctx.out(),
				"{{type=USER_TRACEPOINT, name_pattern=`{}`, filter=`{}`, log_level_rule=",
				name_pattern ? name_pattern : "",
				filter ? filter : "");
			out = details::format_log_level_rule(log_level_rule, out);
			out = format_to(out, ", name_pattern_exclusions=[");
			for (unsigned int i = 0; i < exclusion_count; i++) {
				const char *exclusion = nullptr;
				(void) lttng_event_rule_user_tracepoint_get_name_pattern_exclusion_at_index(
					&rule, i, &exclusion);
				if (i > 0) {
					out = format_to(out, ", ");
				}
				out = format_to(out, "`{}`", exclusion ? exclusion : "");
			}
			return format_to(out, "]}}");
		}
		case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
		case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
		{
			const char *name_pattern = nullptr;
			const char *filter = nullptr;
			const lttng_log_level_rule *log_level_rule = nullptr;
			const char *type_name = "UNKNOWN_LOGGING";

			switch (rule_type) {
			case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
				type_name = "JUL_LOGGING";
				(void) lttng_event_rule_jul_logging_get_name_pattern(&rule,
										     &name_pattern);
				(void) lttng_event_rule_jul_logging_get_filter(&rule, &filter);
				(void) lttng_event_rule_jul_logging_get_log_level_rule(
					&rule, &log_level_rule);
				break;
			case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
				type_name = "LOG4J_LOGGING";
				(void) lttng_event_rule_log4j_logging_get_name_pattern(
					&rule, &name_pattern);
				(void) lttng_event_rule_log4j_logging_get_filter(&rule, &filter);
				(void) lttng_event_rule_log4j_logging_get_log_level_rule(
					&rule, &log_level_rule);
				break;
			case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
				type_name = "LOG4J2_LOGGING";
				(void) lttng_event_rule_log4j2_logging_get_name_pattern(
					&rule, &name_pattern);
				(void) lttng_event_rule_log4j2_logging_get_filter(&rule, &filter);
				(void) lttng_event_rule_log4j2_logging_get_log_level_rule(
					&rule, &log_level_rule);
				break;
			case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
				type_name = "PYTHON_LOGGING";
				(void) lttng_event_rule_python_logging_get_name_pattern(
					&rule, &name_pattern);
				(void) lttng_event_rule_python_logging_get_filter(&rule, &filter);
				(void) lttng_event_rule_python_logging_get_log_level_rule(
					&rule, &log_level_rule);
				break;
			default:
				break;
			}

			auto out = format_to(
				ctx.out(),
				"{{type={}, name_pattern=`{}`, filter=`{}`, log_level_rule=",
				type_name,
				name_pattern ? name_pattern : "",
				filter ? filter : "");
			out = details::format_log_level_rule(log_level_rule, out);
			return format_to(out, "}}");
		}
		case LTTNG_EVENT_RULE_TYPE_UNKNOWN:
		default:
			return format_to(ctx.out(), "{{type=UNKNOWN}}");
		}
	}
};

template <>
struct formatter<lttng_condition_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_condition_type condition_type,
						    FormatContextType& ctx) const
	{
		const char *condition_type_name;

		switch (condition_type) {
		case LTTNG_CONDITION_TYPE_UNKNOWN:
			condition_type_name = "UNKNOWN";
			break;
		case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
			condition_type_name = "SESSION_CONSUMED_SIZE";
			break;
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
			condition_type_name = "BUFFER_USAGE_HIGH";
			break;
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
			condition_type_name = "BUFFER_USAGE_LOW";
			break;
		case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
			condition_type_name = "SESSION_ROTATION_ONGOING";
			break;
		case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
			condition_type_name = "SESSION_ROTATION_COMPLETED";
			break;
		case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
			condition_type_name = "EVENT_RULE_MATCHES";
			break;
		default:
			std::abort();
		}

		return format_to(ctx.out(), "{{type={}}}", condition_type_name);
	}
};

template <>
struct formatter<lttng_condition_status> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_condition_status status,
						    FormatContextType& ctx) const
	{
		const char *name = "Unknown";
		switch (status) {
		case LTTNG_CONDITION_STATUS_OK:
			name = "Ok";
			break;
		case LTTNG_CONDITION_STATUS_ERROR:
			name = "Generic error";
			break;
		case LTTNG_CONDITION_STATUS_UNKNOWN:
			name = "Unknown error";
			break;
		case LTTNG_CONDITION_STATUS_INVALID:
			name = "Invalid parameter";
			break;
		case LTTNG_CONDITION_STATUS_UNSET:
			name = "Unset";
			break;
		case LTTNG_CONDITION_STATUS_UNSUPPORTED:
			name = "Unsupported";
			break;
		}
		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng_reclaim_channel_memory_status> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_reclaim_channel_memory_status status,
						    FormatContextType& ctx) const
	{
		const char *name = "Unknown";

		switch (status) {
		case LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK:
			name = "Success";
			break;
		case LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR:
			name = "Generic error";
			break;
		case LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER:
			name = "Invalid parameter";
			break;
		case LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_RECLAMATION_IN_PROGRESS:
			name = "Reclamation in progress";
			break;
		case LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_NOT_SUPPORTED:
			name = "Not supported";
			break;
		case LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_SESSION_NOT_FOUND:
			name = "Session not found";
			break;
		case LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_CHANNEL_NOT_FOUND:
			name = "Channel not found";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng_reclaim_handle_status> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_reclaim_handle_status status,
						    FormatContextType& ctx) const
	{
		const char *name = "Unknown";

		switch (status) {
		case LTTNG_RECLAIM_HANDLE_STATUS_OK:
			name = "Success";
			break;
		case LTTNG_RECLAIM_HANDLE_STATUS_ERROR:
			name = "Generic error";
			break;
		case LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED:
			name = "Completed";
			break;
		case LTTNG_RECLAIM_HANDLE_STATUS_TIMEOUT:
			name = "Timeout";
			break;
		case LTTNG_RECLAIM_HANDLE_STATUS_INVALID:
			name = "Invalid";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng_error_code> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_error_code error_code,
						    FormatContextType& ctx) const
	{
		return format_to(ctx.out(), lttng_strerror(static_cast<int>(error_code)));
	}
};

template <>
struct formatter<lttng_action_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng_action_type action_type,
						    FormatContextType& ctx) const
	{
		const char *action_type_name;

		switch (action_type) {
		case LTTNG_ACTION_TYPE_UNKNOWN:
			action_type_name = "UNKNOWN";
			break;
		case LTTNG_ACTION_TYPE_NOTIFY:
			action_type_name = "NOTIFY";
			break;
		case LTTNG_ACTION_TYPE_START_SESSION:
			action_type_name = "START_SESSION";
			break;
		case LTTNG_ACTION_TYPE_STOP_SESSION:
			action_type_name = "STOP_SESSION";
			break;
		case LTTNG_ACTION_TYPE_ROTATE_SESSION:
			action_type_name = "ROTATE_SESSION";
			break;
		case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
			action_type_name = "SNAPSHOT_SESSION";
			break;
		case LTTNG_ACTION_TYPE_LIST:
			action_type_name = "LIST";
			break;
		default:
			std::abort();
		}

		return format_to(ctx.out(), action_type_name);
	}
};

namespace details {
template <typename FormatContextIteratorType>
FormatContextIteratorType format_rate_policy(const lttng_rate_policy *policy,
					     FormatContextIteratorType out)
{
	if (!policy) {
		return format_to(out, "(none)");
	}

	const auto type = lttng_rate_policy_get_type(policy);

	switch (type) {
	case LTTNG_RATE_POLICY_TYPE_EVERY_N:
	{
		std::uint64_t interval = 0;
		(void) lttng_rate_policy_every_n_get_interval(policy, &interval);
		return format_to(out, "{{type=EVERY_N, interval={}}}", interval);
	}
	case LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N:
	{
		std::uint64_t threshold = 0;
		(void) lttng_rate_policy_once_after_n_get_threshold(policy, &threshold);
		return format_to(out, "{{type=ONCE_AFTER_N, threshold={}}}", threshold);
	}
	case LTTNG_RATE_POLICY_TYPE_UNKNOWN:
	default:
		return format_to(out, "{{type=UNKNOWN}}");
	}
}
} /* namespace details */

template <>
struct formatter<lttng_condition> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const lttng_condition& condition,
						    FormatContextType& ctx) const
	{
		const auto type = lttng_condition_get_type(&condition);

		switch (type) {
		case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
		{
			const lttng_event_rule *rule = nullptr;
			(void) lttng_condition_event_rule_matches_get_rule(&condition, &rule);

			unsigned int capture_count = 0;
			(void) lttng_condition_event_rule_matches_get_capture_descriptor_count(
				&condition, &capture_count);

			auto out = format_to(ctx.out(), "{{type={}", type);
			if (rule) {
				out = format_to(out, ", rule={}", *rule);
			}
			out = format_to(out, ", capture_descriptors=[");
			for (unsigned int i = 0; i < capture_count; i++) {
				const auto *expr =
					lttng_condition_event_rule_matches_get_capture_descriptor_at_index(
						&condition, i);
				if (i > 0) {
					out = format_to(out, ", ");
				}
				out = format_to(out, "`");
				out = details::format_event_expr(expr, out);
				out = format_to(out, "`");
			}
			return format_to(out, "]}}");
		}
		case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		{
			const char *session_name = nullptr;
			std::uint64_t threshold = 0;

			(void) lttng_condition_session_consumed_size_get_session_name(
				&condition, &session_name);
			(void) lttng_condition_session_consumed_size_get_threshold(&condition,
										   &threshold);

			return format_to(ctx.out(),
					 "{{type={}, session_name=`{}`, threshold_bytes={}}}",
					 type,
					 session_name ? session_name : "",
					 threshold);
		}
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
		{
			const char *session_name = nullptr;
			const char *channel_name = nullptr;
			lttng_domain_type domain = LTTNG_DOMAIN_NONE;

			(void) lttng_condition_buffer_usage_get_session_name(&condition,
									     &session_name);
			(void) lttng_condition_buffer_usage_get_channel_name(&condition,
									     &channel_name);
			(void) lttng_condition_buffer_usage_get_domain_type(&condition, &domain);

			auto out = format_to(
				ctx.out(),
				"{{type={}, session_name=`{}`, channel_name=`{}`, domain={}",
				type,
				session_name ? session_name : "",
				channel_name ? channel_name : "",
				domain);

			std::uint64_t threshold_bytes = 0;
			if (lttng_condition_buffer_usage_get_threshold(
				    &condition, &threshold_bytes) == LTTNG_CONDITION_STATUS_OK) {
				out = format_to(out, ", threshold_bytes={}", threshold_bytes);
			}

			double threshold_ratio = 0.0;
			if (lttng_condition_buffer_usage_get_threshold_ratio(
				    &condition, &threshold_ratio) == LTTNG_CONDITION_STATUS_OK) {
				out = format_to(out, ", threshold_ratio={}", threshold_ratio);
			}

			return format_to(out, "}}");
		}
		case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		{
			const char *session_name = nullptr;
			(void) lttng_condition_session_rotation_get_session_name(&condition,
										 &session_name);
			return format_to(ctx.out(),
					 "{{type={}, session_name=`{}`}}",
					 type,
					 session_name ? session_name : "");
		}
		default:
			return format_to(ctx.out(), "{{type={}}}", type);
		}
	}
};

template <>
struct formatter<lttng_action> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const lttng_action& action,
						    FormatContextType& ctx) const
	{
		const auto type = lttng_action_get_type(&action);

		switch (type) {
		case LTTNG_ACTION_TYPE_LIST:
		{
			unsigned int count = 0;
			(void) lttng_action_list_get_count(&action, &count);

			auto out = format_to(ctx.out(), "{{type={}, count={}, [", type, count);
			for (unsigned int i = 0; i < count; i++) {
				const auto *child = lttng_action_list_get_at_index(&action, i);
				if (i > 0) {
					out = format_to(out, ", ");
				}
				if (child) {
					out = format_to(out, "{}", *child);
				}
			}
			return format_to(out, "]}}");
		}
		case LTTNG_ACTION_TYPE_NOTIFY:
		{
			const lttng_rate_policy *rate_policy = nullptr;
			(void) lttng_action_notify_get_rate_policy(&action, &rate_policy);

			if (rate_policy) {
				auto out = format_to(ctx.out(), "{{type={}, rate_policy=", type);
				out = details::format_rate_policy(rate_policy, out);
				return format_to(out, "}}");
			}

			return format_to(ctx.out(), "{{type={}}}", type);
		}
		case LTTNG_ACTION_TYPE_START_SESSION:
		case LTTNG_ACTION_TYPE_STOP_SESSION:
		case LTTNG_ACTION_TYPE_ROTATE_SESSION:
		case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
		{
			const char *session_name = nullptr;
			const lttng_rate_policy *rate_policy = nullptr;

			switch (type) {
			case LTTNG_ACTION_TYPE_START_SESSION:
				(void) lttng_action_start_session_get_session_name(&action,
										   &session_name);
				(void) lttng_action_start_session_get_rate_policy(&action,
										  &rate_policy);
				break;
			case LTTNG_ACTION_TYPE_STOP_SESSION:
				(void) lttng_action_stop_session_get_session_name(&action,
										  &session_name);
				(void) lttng_action_stop_session_get_rate_policy(&action,
										 &rate_policy);
				break;
			case LTTNG_ACTION_TYPE_ROTATE_SESSION:
				(void) lttng_action_rotate_session_get_session_name(&action,
										    &session_name);
				(void) lttng_action_rotate_session_get_rate_policy(&action,
										   &rate_policy);
				break;
			case LTTNG_ACTION_TYPE_SNAPSHOT_SESSION:
				(void) lttng_action_snapshot_session_get_session_name(
					&action, &session_name);
				(void) lttng_action_snapshot_session_get_rate_policy(&action,
										     &rate_policy);
				break;
			default:
				break;
			}

			auto out = format_to(ctx.out(),
					     "{{type={}, session_name=`{}`",
					     type,
					     session_name ? session_name : "");
			if (rate_policy) {
				out = format_to(out, ", rate_policy=");
				out = details::format_rate_policy(rate_policy, out);
			}
			return format_to(out, "}}");
		}
		default:
			return format_to(ctx.out(), "{{type={}}}", type);
		}
	}
};
} /* namespace fmt */

#endif /* LTTNG_COMMON_CTL_FORMAT_H */
