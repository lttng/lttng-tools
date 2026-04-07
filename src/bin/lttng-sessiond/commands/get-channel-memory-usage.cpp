/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "get-channel-memory-usage.hpp"

#include <common/exception.hpp>

#ifdef HAVE_LIBLTTNG_UST_CTL

#include <common/error.hpp>
#include <common/format.hpp>

namespace lsc = lttng::sessiond::commands;

namespace {
void validate_agent_channel_name(lttng::domain_class domain, lttng::c_string_view channel_name)
{
	const auto expected_channel_name = [domain]() {
		switch (domain) {
		case lttng::domain_class::LOG4J:
			return DEFAULT_LOG4J_CHANNEL_NAME;
		case lttng::domain_class::LOG4J2:
			return DEFAULT_LOG4J2_CHANNEL_NAME;
		case lttng::domain_class::JAVA_UTIL_LOGGING:
			return DEFAULT_JUL_CHANNEL_NAME;
		case lttng::domain_class::PYTHON_LOGGING:
			return DEFAULT_PYTHON_CHANNEL_NAME;
		default:
			std::abort();
		}
	}();

	if (expected_channel_name != channel_name) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
			"Invalid channel name for agent domain: domain={}, expected_name=`{}`, channel_name=`{}`",
			domain,
			expected_channel_name,
			channel_name));
	}
}
} /* namespace */

std::vector<lsc::stream_memory_usage_group>
lsc::get_channel_memory_usage(const ltt_session::locked_ref& session,
			      lttng::domain_class domain,
			      lttng::c_string_view channel_name)
{
	DBG_FMT("Getting memory usage for channel: session_name=`{}`, domain={}, channel_name=`{}`",
		session->name,
		domain,
		channel_name);

	switch (domain) {
	case lttng::domain_class::LOG4J:
	case lttng::domain_class::LOG4J2:
	case lttng::domain_class::JAVA_UTIL_LOGGING:
	case lttng::domain_class::PYTHON_LOGGING:
		/* Throws when the channel name is invalid. */
		validate_agent_channel_name(domain, channel_name);
		break;
	case lttng::domain_class::USER_SPACE:
		break;
	case lttng::domain_class::KERNEL_SPACE:
		LTTNG_THROW_UNSUPPORTED_ERROR(
			"Getting the memory usage for channels in the kernel domain is not supported");
	default:
		ERR_FMT("Unexpected domain class: domain={}", domain);
		std::abort();
	}

	const auto& target_channel_config = session->get_domain(domain).get_channel(channel_name);

	return session->get_ust_orchestrator().get_channel_memory_usage(target_channel_config);
}

#else /* !HAVE_LIBLTTNG_UST_CTL */

namespace lsc = lttng::sessiond::commands;

std::vector<lsc::stream_memory_usage_group>
lsc::get_channel_memory_usage(const ltt_session::locked_ref& session [[maybe_unused]],
			      lttng::domain_class domain [[maybe_unused]],
			      lttng::c_string_view channel_name [[maybe_unused]])
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Getting the channel memory usage is not supported by a sessiond built without UST support");
}

#endif /* HAVE_LIBLTTNG_UST_CTL */
