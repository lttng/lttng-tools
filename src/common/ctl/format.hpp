/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_CTL_FORMAT_H
#define LTTNG_COMMON_CTL_FORMAT_H

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

template <>
struct formatter<lttng_event_rule> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const lttng_event_rule& rule,
						    FormatContextType& ctx) const
	{
		const auto rule_type = lttng_event_rule_get_type(&rule);
		const char *rule_type_name;

		switch (rule_type) {
		case LTTNG_EVENT_RULE_TYPE_UNKNOWN:
			rule_type_name = "UNKNOWN";
			break;
		case LTTNG_EVENT_RULE_TYPE_KERNEL_SYSCALL:
			rule_type_name = "KERNEL_SYSCALL";
			break;
		case LTTNG_EVENT_RULE_TYPE_KERNEL_KPROBE:
			rule_type_name = "KERNEL_KPROBE";
			break;
		case LTTNG_EVENT_RULE_TYPE_KERNEL_TRACEPOINT:
			rule_type_name = "KERNEL_TRACEPOINT";
			break;
		case LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE:
			rule_type_name = "KERNEL_UPROBE";
			break;
		case LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT:
			rule_type_name = "USER_TRACEPOINT";
			break;
		case LTTNG_EVENT_RULE_TYPE_JUL_LOGGING:
			rule_type_name = "JUL_LOGGING";
			break;
		case LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING:
			rule_type_name = "LOG4J_LOGGING";
			break;
		case LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING:
			rule_type_name = "PYTHON_LOGGING";
			break;
		case LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING:
			rule_type_name = "LOG4J2_LOGGING";
			break;
		default:
			std::abort();
		}

		return format_to(ctx.out(), "{{type={}}}", rule_type_name);
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

} /* namespace fmt */

#endif /* LTTNG_COMMON_CTL_FORMAT_H */
