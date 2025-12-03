/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "bin/lttng-sessiond/recording-channel-configuration.hpp"
#include "reclaim-channel-memory.hpp"
#include "vendor/optional.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/urcu.hpp>

#include <bin/lttng-sessiond/consumer.hpp>
#include <numeric>
#include <unordered_map>

namespace lsc = lttng::sessiond::commands;

using channel_description_map = std::unordered_map<
	std::pair<std::uint64_t, lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness>,
	lttng::sessiond::user_space_consumer_channel_keys::iterator::key>;

/*
 * Provide a hash function for the channel description map key (pair of stream group id and
 * bitness).
 */
namespace std {
template <>
struct hash<std::pair<std::uint64_t,
		      lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness>> {
	std::size_t operator()(
		const std::pair<std::uint64_t,
				lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness>&
			p) const noexcept
	{
		const auto key_hash = std::hash<std::uint64_t>{}(p.first);
		const auto bitness_hash = std::hash<std::underlying_type<
			lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness>::type>{}(
			static_cast<std::underlying_type<
				lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness>::
					    type>(p.second));

		/* Combine the two hashes. */
		return key_hash ^ bitness_hash;
	}
};
} /* namespace std */

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
 * The results are matched back to the channel descriptions provided to
 * populate the result vector providing proper stream group ownership
 * information along with the reclaimed memory sizes (completed and pending).
 */
void issue_consumer_reclaim_channel_memory(
	consumer_socket& consumer_socket,
	lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness bitness,
	const ltt_session::locked_ref& session,
	const channel_description_map& channel_descriptions,
	bool is_per_cpu_stream,
	const std::vector<std::uint64_t>& target_consumer_channel_keys,
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
	bool only_reclaim_consumed_data,
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
								   only_reclaim_consumed_data);

	for (const auto& channel_reclaimed_memory : channels_reclaimed_memory) {
		const auto it = channel_descriptions.find(std::make_pair(
			target_consumer_channel_keys.at(current_channel_index), bitness));
		if (it == channel_descriptions.end()) {
			LTTNG_THROW_ERROR(fmt::format(
				"Consumer channel key not found in channel descriptions: key={}, bitness={}",
				target_consumer_channel_keys.at(current_channel_index),
				static_cast<int>(bitness)));
		}

		const auto& channel_description = it->second;

		const auto group_owner = [&session, &channel_description]() {
			switch (session->ust_session->buffer_type) {
			case LTTNG_BUFFER_PER_PID:
				return lsc::stream_group_owner(channel_description.bitness,
							       channel_description.owner_pid());
			case LTTNG_BUFFER_PER_UID:
				return lsc::stream_group_owner(channel_description.bitness,
							       channel_description.owner_uid());
			default:
				std::abort();
			}
		}();

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
				stream_reclaimed_memory.reclaimed_bytes,
				stream_reclaimed_memory.pending_bytes_to_reclaim);
		}

		result.emplace_back(group_owner, std::move(streams_reclaimed_memory));

		current_channel_index++;
	}
}
} /* namespace */

std::vector<lsc::stream_memory_reclamation_result_group> lsc::reclaim_channel_memory(
	const ltt_session::locked_ref& session,
	lttng::domain_class domain,
	lttng::c_string_view channel_name,
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
	bool require_consumed)
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

	const auto is_per_cpu_stream =
		session->get_domain(domain).get_channel(channel_name).buffer_allocation_policy ==
		lttng::sessiond::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU;

	channel_description_map channel_descriptions;

	/*
	 * Iterate on all consumer daemon channels that map to the channel_name to build a list
	 * of keys for which we will request memory usage statistics.
	 */
	std::vector<std::uint64_t> consumer32_channel_keys, consumer64_channel_keys;
	for (const auto consumer_channel_description :
	     session->user_space_consumer_channel_keys(channel_name)) {
		if (consumer_channel_description.bitness ==
		    lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness::ABI_32) {
			consumer32_channel_keys.emplace_back(
				consumer_channel_description.consumer_key);
		} else {
			consumer64_channel_keys.emplace_back(
				consumer_channel_description.consumer_key);
		}

		channel_descriptions.emplace(
			std::make_pair(consumer_channel_description.consumer_key,
				       consumer_channel_description.bitness),
			consumer_channel_description);
	}

	std::vector<lsc::stream_memory_reclamation_result_group> result;
	/* Handle 32-bit ABI stream groups. */
	if (!consumer32_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		issue_consumer_reclaim_channel_memory(
			*consumer_find_socket_by_bitness(32, session->ust_session->consumer),
			lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness::ABI_32,
			session,
			channel_descriptions,
			is_per_cpu_stream,
			consumer32_channel_keys,
			reclaim_older_than_age,
			require_consumed,
			result);
	}

	/* Handle 64-bit ABI stream groups. */
	if (!consumer64_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		issue_consumer_reclaim_channel_memory(
			*consumer_find_socket_by_bitness(64, session->ust_session->consumer),
			lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness::ABI_64,
			session,
			channel_descriptions,
			is_per_cpu_stream,
			consumer64_channel_keys,
			reclaim_older_than_age,
			require_consumed,
			result);
	}

	/* Log results. */
	for (const auto& stream_group : result) {
		DBG_FMT("Reclaimed memory for streams in group:session_name=`{}`, domain={}, channel_name=`{}`, "
			"owner_type={}, bitness={}, streams_count={}, total_reclaimed={} bytes",
			session->name,
			domain,
			channel_name,
			stream_group.owner.owner_type,
			stream_group.owner.bitness,
			stream_group.reclaimed_streams_memory.size(),
			std::accumulate(
				stream_group.reclaimed_streams_memory.begin(),
				stream_group.reclaimed_streams_memory.end(),
				0ULL,
				[](std::uint64_t sum,
				   const lsc::stream_memory_reclamation_result& stream_result) {
					return sum + stream_result.bytes_reclaimed;
				}));

		for (const auto& stream_result : stream_group.reclaimed_streams_memory) {
			DBG_FMT("Reclaimed stream memory: id={}, bytes_reclaimed={}",
				stream_result.id,
				stream_result.bytes_reclaimed);
		}
	}

	return result;
}
