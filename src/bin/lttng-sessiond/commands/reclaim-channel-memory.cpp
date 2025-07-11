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

		/* Combine the two hashes */
		return key_hash ^ bitness_hash;
	}
};
} /* namespace std */

namespace {
void validate_agent_channel_name(lttng::sessiond::domain_class domain,
				 lttng::c_string_view channel_name)
{
	const auto expected_channel_name = [domain]() {
		switch (domain) {
		case lttng::sessiond::domain_class::LOG4J:
			return DEFAULT_LOG4J_CHANNEL_NAME;
		case lttng::sessiond::domain_class::LOG4J2:
			return DEFAULT_LOG4J2_CHANNEL_NAME;
		case lttng::sessiond::domain_class::JAVA_UTIL_LOGGING:
			return DEFAULT_JUL_CHANNEL_NAME;
		case lttng::sessiond::domain_class::PYTHON_LOGGING:
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

void reclaim_consumer_channel_memory(
	std::vector<lsc::stream_memory_reclamation_result_group>& result,
	const std::vector<std::uint64_t>& consumer_channel_keys,
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than,
	bool require_consumed,
	lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness bitness,
	const channel_description_map& channel_descriptions,
	const ltt_session::locked_ref& session,
	bool is_per_cpu_stream,
	consumer_socket& consumer_socket)
{
	if (consumer_channel_keys.empty()) {
		return;
	}

	std::size_t current_channel_index = 0;
	const auto channels_reclaimed_memory = lttng::sessiond::consumer::reclaim_channels_memory(
		consumer_socket, consumer_channel_keys, reclaim_older_than, require_consumed);

	for (const auto& channel_reclaimed_memory : channels_reclaimed_memory) {
		const auto& channel_description =
			channel_descriptions
				.find(std::make_pair(
					consumer_channel_keys.at(current_channel_index), bitness))
				->second;

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
				stream_identifier, stream_reclaimed_memory.reclaimed_bytes);
		}

		result.emplace_back(group_owner, std::move(streams_reclaimed_memory));

		current_channel_index++;
	}
}
} /* namespace */

std::vector<lsc::stream_memory_reclamation_result_group>
lsc::reclaim_channel_memory(const ltt_session::locked_ref& session,
			    lttng::sessiond::domain_class domain,
			    lttng::c_string_view channel_name,
			    const nonstd::optional<std::chrono::microseconds>& reclaim_older_than,
			    bool require_consumed)
{
	DBG_FMT("Reclaiming memory for channel: session_name=`{}`, domain={}, channel_name=`{}`, age_older_than={}, require_consumed={}",
		session->name,
		domain,
		channel_name,
		reclaim_older_than ? fmt::format("{}us", reclaim_older_than->count()) : "none",
		require_consumed);

	switch (domain) {
	case lttng::sessiond::domain_class::LOG4J:
	case lttng::sessiond::domain_class::LOG4J2:
	case lttng::sessiond::domain_class::JAVA_UTIL_LOGGING:
	case lttng::sessiond::domain_class::PYTHON_LOGGING:
		/* Throws when the channel name is invalid. */
		validate_agent_channel_name(domain, channel_name);
		break;
	case lttng::sessiond::domain_class::USER_SPACE:
		break;
	case lttng::sessiond::domain_class::KERNEL_SPACE:
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
	if (!consumer32_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		reclaim_consumer_channel_memory(
			result,
			consumer32_channel_keys,
			reclaim_older_than,
			require_consumed,
			lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness::ABI_32,
			channel_descriptions,
			session,
			is_per_cpu_stream,
			*consumer_find_socket_by_bitness(32, session->ust_session->consumer));
	}

	if (!consumer64_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		reclaim_consumer_channel_memory(
			result,
			consumer64_channel_keys,
			reclaim_older_than,
			require_consumed,
			lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness::ABI_64,
			channel_descriptions,
			session,
			is_per_cpu_stream,
			*consumer_find_socket_by_bitness(64, session->ust_session->consumer));
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
