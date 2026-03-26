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
#include <common/urcu.hpp>

#include <bin/lttng-sessiond/consumer.hpp>
#include <bin/lttng-sessiond/recording-channel-configuration.hpp>
#include <bin/lttng-sessiond/ust-domain-orchestrator.hpp>

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

void append_consumer_channel_memory_usage(
	std::vector<lsc::stream_memory_usage_group>& result,
	const std::vector<std::uint64_t>& consumer_channel_keys,
	const std::vector<lsc::stream_group_owner>& stream_group_owners,
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
		const auto& group_owner = stream_group_owners.at(current_channel_index);

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

	std::vector<lsc::stream_memory_usage_group> result;
	if (!consumer32_channel_keys.empty()) {
		/* Protect looked-up consumer socket. */
		const lttng::urcu::read_lock_guard read_lock;

		append_consumer_channel_memory_usage(
			result,
			consumer32_channel_keys,
			consumer32_owners,
			is_per_cpu_stream,
			*consumer_find_socket_by_bitness(32, session->ust_session->consumer));
	}

	if (!consumer64_channel_keys.empty()) {
		/* Protect looked-up consumer socket. */
		const lttng::urcu::read_lock_guard read_lock;

		append_consumer_channel_memory_usage(
			result,
			consumer64_channel_keys,
			consumer64_owners,
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
