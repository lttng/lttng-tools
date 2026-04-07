/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CHANNEL_MEMORY_TYPES_HPP
#define LTTNG_SESSIOND_CHANNEL_MEMORY_TYPES_HPP

#include <common/format.hpp>

#include <vendor/optional.hpp>

#include <bin/lttng-sessiond/ust-application-abi.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <vector>

namespace lttng {
namespace sessiond {
namespace commands {

struct stream_group_owner {
	stream_group_owner(ust::application_abi bitness_, pid_t pid_) noexcept :
		owner_type(type::PROCESS), bitness(bitness_), id{ .pid = pid_ }
	{
	}

	stream_group_owner(ust::application_abi bitness_, uid_t uid_) noexcept :
		owner_type(type::USER), bitness(bitness_), id{ .uid = uid_ }
	{
	}

	enum class type : std::uint8_t {
		USER,
		PROCESS,
		/*
		 * SYSTEM is unused as memory usage can't be reported by the kernel tracer at the
		 * moment.
		 */
		SYSTEM,
	};

	const type owner_type;
	const ust::application_abi bitness;
	const union {
		pid_t pid;
		uid_t uid;
	} id;
};

struct stream_identifier {
	/* nonstd::nullopt if using per-channel allocation. */
	const nonstd::optional<uint32_t> cpu_id;
};

struct stream_memory_usage {
	stream_memory_usage(stream_identifier _id,
			    std::uint64_t logical_size_bytes_,
			    std::uint64_t physical_size_bytes_) :
		id(std::move(_id)),
		size_bytes{ .logical = logical_size_bytes_, .physical = physical_size_bytes_ }
	{
	}

	const stream_identifier id;
	const struct {
		std::uint64_t logical;
		std::uint64_t physical;
	} size_bytes;
};

struct stream_memory_usage_group {
	stream_memory_usage_group(stream_group_owner owner_,
				  std::vector<stream_memory_usage> streams_memory_usage_) :
		owner(std::move(owner_)), streams_memory_usage(std::move(streams_memory_usage_))
	{
	}

	const stream_group_owner owner;
	const std::vector<stream_memory_usage> streams_memory_usage;
};

struct stream_memory_reclamation_result {
	stream_memory_reclamation_result(stream_identifier _id,
					 std::uint64_t subbuffers_reclaimed_,
					 std::uint64_t pending_subbuffers_to_reclaim_) :
		id(std::move(_id)),
		subbuffers_reclaimed(subbuffers_reclaimed_),
		pending_subbuffers_to_reclaim(pending_subbuffers_to_reclaim_)
	{
	}

	const stream_identifier id;
	const std::uint64_t subbuffers_reclaimed;
	const std::uint64_t pending_subbuffers_to_reclaim;
};

struct stream_memory_reclamation_result_group {
	stream_memory_reclamation_result_group(
		stream_group_owner owner_,
		std::vector<stream_memory_reclamation_result> reclaimed_streams_memory_) :
		owner(std::move(owner_)),
		reclaimed_streams_memory(std::move(reclaimed_streams_memory_))
	{
	}

	const stream_group_owner owner;
	const std::vector<stream_memory_reclamation_result> reclaimed_streams_memory;
};

struct reclaim_channel_memory_result {
	std::vector<stream_memory_reclamation_result_group> groups;
	/* Token for tracking async completion. */
	std::uint64_t token;
};

/* Completion callback signature: bool parameter indicates success (true) or failure (false). */
using completion_callback_t = std::function<void(bool)>;
using cancellation_callback_t = std::function<void()>;

} /* namespace commands */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::commands::stream_group_owner::type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::commands::stream_group_owner::type owner_type,
	       FormatContextType& ctx) const
	{
		auto name = "unknown";

		switch (owner_type) {
		case lttng::sessiond::commands::stream_group_owner::type::USER:
			name = "user";
			break;
		case lttng::sessiond::commands::stream_group_owner::type::PROCESS:
			name = "process";
			break;
		case lttng::sessiond::commands::stream_group_owner::type::SYSTEM:
			name = "system";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng::sessiond::commands::stream_identifier> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(const lttng::sessiond::commands::stream_identifier& stream_id,
	       FormatContextType& ctx) const
	{
		if (stream_id.cpu_id) {
			return format_to(ctx.out(), "cpu {}", *stream_id.cpu_id);
		} else {
			return format_to(ctx.out(), "per-channel stream");
		}
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_CHANNEL_MEMORY_TYPES_HPP */
