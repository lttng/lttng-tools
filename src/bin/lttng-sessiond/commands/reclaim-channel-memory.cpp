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
#include <common/urcu.hpp>

#include <bin/lttng-sessiond/consumer.hpp>
#include <bin/lttng-sessiond/pending-memory-reclamation-request.hpp>
#include <bin/lttng-sessiond/recording-channel-configuration.hpp>
#include <bin/lttng-sessiond/ust-domain-orchestrator.hpp>
#include <numeric>

namespace lsc = lttng::sessiond::commands;
namespace lsu = lttng::sessiond::ust;

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

/*
 * Issue a memory reclamation request for the specified consumer channel keys
 * (effectively stream groups).
 *
 * The results are matched back to the stream group owners provided to
 * populate the result vector providing proper stream group ownership
 * information along with the reclaimed memory sizes (completed and pending).
 */
void issue_consumer_reclaim_channel_memory(
	consumer_socket& consumer_socket,
	const std::vector<lsc::stream_group_owner>& stream_group_owners,
	bool is_per_cpu_stream,
	const std::vector<std::uint64_t>& target_consumer_channel_keys,
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
	bool only_reclaim_consumed_data,
	std::uint64_t memory_reclaim_request_token,
	std::vector<lsc::stream_memory_reclamation_result_group>& result)
{
	if (target_consumer_channel_keys.empty()) {
		return;
	}

	std::size_t current_channel_index = 0;
	const auto channels_reclaimed_memory =
		lttng::sessiond::consumer::reclaim_channels_memory(consumer_socket,
								   target_consumer_channel_keys,
								   reclaim_older_than_age,
								   only_reclaim_consumed_data,
								   memory_reclaim_request_token);

	for (const auto& channel_reclaimed_memory : channels_reclaimed_memory) {
		const auto& group_owner = stream_group_owners.at(current_channel_index);

		std::uint64_t cpu_id = 0;
		std::vector<lsc::stream_memory_reclamation_result> streams_reclaimed_memory;
		for (const auto& stream_reclaimed_memory :
		     channel_reclaimed_memory.streams_reclaimed_memory) {
			const lsc::stream_identifier stream_identifier{
				is_per_cpu_stream ?
					decltype(lsc::stream_identifier::cpu_id)(cpu_id++) :
					nonstd::nullopt
			};

			streams_reclaimed_memory.emplace_back(
				stream_identifier,
				stream_reclaimed_memory.subbuffers_reclaimed,
				stream_reclaimed_memory.pending_subbuffers_to_reclaim);
		}

		result.emplace_back(group_owner, std::move(streams_reclaimed_memory));

		current_channel_index++;
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
	const auto is_per_cpu_stream = target_channel_config.buffer_allocation_policy ==
		lttng::sessiond::config::recording_channel_configuration::
			buffer_allocation_policy_t::PER_CPU;

	const auto& orchestrator =
		static_cast<const lsu::domain_orchestrator&>(session->get_ust_orchestrator());

	/*
	 * Iterate all consumer stream groups via the orchestrator, filtering for
	 * data channels that belong to the target channel configuration. Build
	 * per-bitness key vectors and parallel owner vectors for batch-querying
	 * the consumer daemons.
	 */
	std::vector<std::uint64_t> consumer32_channel_keys, consumer64_channel_keys;
	std::vector<lsc::stream_group_owner> consumer32_owners, consumer64_owners;

	orchestrator.for_each_consumer_stream_group(
		[&target_channel_config,
		 &consumer32_channel_keys,
		 &consumer64_channel_keys,
		 &consumer32_owners,
		 &consumer64_owners](
			const lsu::domain_orchestrator::consumer_stream_group_descriptor& desc) {
			/* Only consider data channels. */
			if (desc.is_metadata) {
				return;
			}

			/*
			 * Filter by channel configuration pointer identity: the
			 * orchestrator passes the actual recording_channel_configuration
			 * reference from the stream group key.
			 */
			if (&desc.channel_config != &target_channel_config) {
				return;
			}

			const auto owner = [&desc]() {
				if (desc.owner_uid) {
					return lsc::stream_group_owner(desc.abi, *desc.owner_uid);
				}

				return lsc::stream_group_owner(desc.abi, *desc.owner_pid);
			}();

			if (desc.abi == lsu::application_abi::ABI_32) {
				consumer32_channel_keys.emplace_back(desc.consumer_key);
				consumer32_owners.emplace_back(owner);
			} else {
				consumer64_channel_keys.emplace_back(desc.consumer_key);
				consumer64_owners.emplace_back(owner);
			}
		});

	const unsigned int consumer_count = (!consumer32_channel_keys.empty() ? 1 : 0) +
		(!consumer64_channel_keys.empty() ? 1 : 0);

	/*
	 * Create the completion tracking request before issuing reclaim operations.
	 * The consumers will signal completion on their own when they're done.
	 */
	DBG_FMT("Creating completion tracking request: consumer_count={}", consumer_count);

	const auto token = lttng::sessiond::the_pending_memory_reclamation_registry.create_request(
		*session,
		channel_name,
		consumer_count,
		std::move(on_complete),
		std::move(on_cancel));

	/*
	 * Issue reclaim requests with the token. Consumers will report completion
	 * when they're done processing any pending sub-buffers.
	 */
	std::vector<lsc::stream_memory_reclamation_result_group> result;

	/* Handle 32-bit ABI stream groups. */
	if (!consumer32_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		try {
			issue_consumer_reclaim_channel_memory(
				*consumer_find_socket_by_bitness(
					32,
					&static_cast<lttng::sessiond::ust::domain_orchestrator&>(
						 session->get_ust_orchestrator())
						 .get_consumer_output()),
				consumer32_owners,
				is_per_cpu_stream,
				consumer32_channel_keys,
				reclaim_older_than_age,
				require_consumed,
				token,
				result);
		} catch (const std::exception& e) {
			/* Clean up the pending request on error. */
			lttng::sessiond::the_pending_memory_reclamation_registry.cancel_request(
				token);
			throw;
		}
	}

	/* Handle 64-bit ABI stream groups. */
	if (!consumer64_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		try {
			issue_consumer_reclaim_channel_memory(
				*consumer_find_socket_by_bitness(
					64,
					&static_cast<lttng::sessiond::ust::domain_orchestrator&>(
						 session->get_ust_orchestrator())
						 .get_consumer_output()),
				consumer64_owners,
				is_per_cpu_stream,
				consumer64_channel_keys,
				reclaim_older_than_age,
				require_consumed,
				token,
				result);
		} catch (const std::exception& e) {
			/* Clean up the pending request on error. */
			lttng::sessiond::the_pending_memory_reclamation_registry.cancel_request(
				token);
			throw;
		}
	}

	/* Log results. */
	for (const auto& stream_group : result) {
		const auto total_reclaimed = std::accumulate(
			stream_group.reclaimed_streams_memory.begin(),
			stream_group.reclaimed_streams_memory.end(),
			0ULL,
			[](std::uint64_t sum,
			   const lsc::stream_memory_reclamation_result& stream_result) {
				return sum + stream_result.subbuffers_reclaimed;
			});
		const auto total_pending = std::accumulate(
			stream_group.reclaimed_streams_memory.begin(),
			stream_group.reclaimed_streams_memory.end(),
			0ULL,
			[](std::uint64_t sum,
			   const lsc::stream_memory_reclamation_result& stream_result) {
				return sum + stream_result.pending_subbuffers_to_reclaim;
			});

		DBG_FMT("Reclaimed sub-buffers for streams in group: session_name=`{}`, domain={}, channel_name=`{}`, "
			"owner_type={}, bitness={}, streams_count={}, total_reclaimed={}, total_pending={}",
			session->name,
			domain,
			channel_name,
			stream_group.owner.owner_type,
			stream_group.owner.bitness,
			stream_group.reclaimed_streams_memory.size(),
			total_reclaimed,
			total_pending);

		for (const auto& stream_result : stream_group.reclaimed_streams_memory) {
			DBG_FMT("Reclaimed stream sub-buffers: id={}, subbuffers_reclaimed={}, pending_subbuffers={}",
				stream_result.id,
				stream_result.subbuffers_reclaimed,
				stream_result.pending_subbuffers_to_reclaim);
		}
	}

	return { std::move(result), token };
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
