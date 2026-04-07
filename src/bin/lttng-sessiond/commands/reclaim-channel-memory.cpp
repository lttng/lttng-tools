/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "reclaim-channel-memory.hpp"

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

lsc::reclaim_channel_memory_result lsc::reclaim_channel_memory(
	const ltt_session::locked_ref& session,
	lttng::domain_class domain,
	lttng::c_string_view channel_name,
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
	bool require_consumed,
	lsc::completion_callback_t on_complete,
	lsc::cancellation_callback_t on_cancel)
{
	DBG_FMT("Reclaiming memory for channel: session_name=`{}`, domain={}, channel_name=`{}`, age_older_than={}, require_consumed={}",
		session->name,
		domain,
		channel_name,
		reclaim_older_than_age ? fmt::format("{}us", reclaim_older_than_age->count()) :
					 "none",
		require_consumed);

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
			"Reclaiming channel memory for channels in the kernel domain is not supported");
	default:
		ERR_FMT("Unexpected domain class: domain={}", domain);
		std::abort();
	}

	const auto& target_channel_config = session->get_domain(domain).get_channel(channel_name);

	return session->get_ust_orchestrator().reclaim_channel_memory(target_channel_config,
								      reclaim_older_than_age,
								      require_consumed,
								      std::move(on_complete),
								      std::move(on_cancel));
}

#else /* !HAVE_LIBLTTNG_UST_CTL */

namespace lsc = lttng::sessiond::commands;

lsc::reclaim_channel_memory_result lsc::reclaim_channel_memory(
	const ltt_session::locked_ref& session [[maybe_unused]],
	lttng::domain_class domain [[maybe_unused]],
	lttng::c_string_view channel_name [[maybe_unused]],
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age [[maybe_unused]],
	bool require_consumed [[maybe_unused]],
	lsc::completion_callback_t on_complete [[maybe_unused]],
	lsc::cancellation_callback_t on_cancel [[maybe_unused]])
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Reclaiming channel memory is not supported by a sessiond built without UST support");
}

#endif /* HAVE_LIBLTTNG_UST_CTL */
