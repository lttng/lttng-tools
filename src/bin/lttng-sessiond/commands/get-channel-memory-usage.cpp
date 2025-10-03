/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "bin/lttng-sessiond/recording-channel-configuration.hpp"
#include "get-channel-memory-usage.hpp"
#include "vendor/optional.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/urcu.hpp>

#include <bin/lttng-sessiond/consumer.hpp>
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

void append_consumer_channel_memory_usage(
	std::vector<lsc::stream_memory_usage_group>& result,
	const std::vector<std::uint64_t>& consumer_channel_keys,
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
	const auto channels_memory_usage = lttng::sessiond::consumer::get_channels_memory_usage(
		consumer_socket, consumer_channel_keys);

	for (const auto& channel_usage : channels_memory_usage) {
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
		std::vector<lsc::stream_memory_usage> streams_memory_usage;
		for (const auto& stream_usage : channel_usage.streams_memory_usage) {
			const lsc::stream_identifier stream_identifier{
				is_per_cpu_stream ?
					decltype(lsc::stream_identifier::cpu_id)(cpu_id++) :
					nonstd::nullopt
			};

			streams_memory_usage.emplace_back(stream_identifier,
							  stream_usage.size_bytes.logical,
							  stream_usage.size_bytes.physical);
		}

		result.emplace_back(group_owner, std::move(streams_memory_usage));

		current_channel_index++;
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

	std::vector<lsc::stream_memory_usage_group> result;
	if (!consumer32_channel_keys.empty()) {
		/* Protect looked-up consumer socket. */
		const lttng::urcu::read_lock_guard read_lock;

		append_consumer_channel_memory_usage(
			result,
			consumer32_channel_keys,
			lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness::ABI_32,
			channel_descriptions,
			session,
			is_per_cpu_stream,
			*consumer_find_socket_by_bitness(32, session->ust_session->consumer));
	}

	if (!consumer64_channel_keys.empty()) {
		/* Protect looked-up consumer socket. */
		const lttng::urcu::read_lock_guard read_lock;

		append_consumer_channel_memory_usage(
			result,
			consumer64_channel_keys,
			lttng::sessiond::user_space_consumer_channel_keys::consumer_bitness::ABI_64,
			channel_descriptions,
			session,
			is_per_cpu_stream,
			*consumer_find_socket_by_bitness(64, session->ust_session->consumer));
	}

	/* Log results. */
	for (const auto& stream_group : result) {
		DBG_FMT("Stream group memory usage: session_name=`{}`, domain={}, channel_name=`{}`, "
			"owner_type={}, bitness={}, streams_count={}, usage_ratio={:.3f}%",
			session->name,
			domain,
			channel_name,
			stream_group.owner.owner_type,
			stream_group.owner.bitness,
			stream_group.streams_memory_usage.size(),
			[&stream_group]() {
				if (stream_group.streams_memory_usage.empty()) {
					return 0.0;
				}

				std::uint64_t logical_size = 0, physical_size = 0;
				for (const auto& usage : stream_group.streams_memory_usage) {
					logical_size += usage.size_bytes.logical;
					physical_size += usage.size_bytes.physical;
				}

				if (logical_size == 0) {
					return 0.0;
				}

				return (static_cast<double>(physical_size) / logical_size) * 100.0;
			}());

		for (const auto& stream_usage : stream_group.streams_memory_usage) {
			DBG_FMT("Stream memory usage: id='{}', logical_size_bytes={}, "
				"physical_size_bytes={}",
				stream_usage.id,
				stream_usage.size_bytes.logical,
				stream_usage.size_bytes.physical);
		}
	}

	return result;
}
