/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CMD_RECLAIM_CHANNEL_MEMORY_HPP
#define LTTNG_SESSIOND_CMD_RECLAIM_CHANNEL_MEMORY_HPP

#include <common/string-utils/c-string-view.hpp>

#include <vendor/optional.hpp>

#include <bin/lttng-sessiond/commands/get-channel-memory-usage.hpp>
#include <bin/lttng-sessiond/domain.hpp>
#include <bin/lttng-sessiond/pending-memory-reclamation-request.hpp>
#include <bin/lttng-sessiond/session.hpp>
#include <chrono>
#include <vector>

namespace lttng {
namespace sessiond {
namespace commands {

struct stream_memory_reclamation_result {
	stream_memory_reclamation_result(stream_identifier _id,
					 std::uint64_t bytes_reclaimed_,
					 std::uint64_t pending_bytes_to_reclaim_) :
		id(std::move(_id)),
		bytes_reclaimed(bytes_reclaimed_),
		pending_bytes_to_reclaim(pending_bytes_to_reclaim_)
	{
	}

	const stream_identifier id;
	const std::uint64_t bytes_reclaimed;
	const std::uint64_t pending_bytes_to_reclaim;
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
	lttng::sessiond::pending_memory_reclamation_registry::token_t token;
};

/* Completion callback signature: bool parameter indicates success (true) or failure (false). */
using completion_callback_t = std::function<void(bool)>;
using cancellation_callback_t = std::function<void()>;

reclaim_channel_memory_result
reclaim_channel_memory(const ltt_session::locked_ref& session,
		       lttng::domain_class domain,
		       lttng::c_string_view channel_name,
		       const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
		       bool require_consumed,
		       completion_callback_t on_complete,
		       cancellation_callback_t on_cancel);

} /* namespace commands */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt
 * namespace, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {

} /* namespace fmt */

#endif /* LTTNG_SESSIOND_CMD_RECLAIM_CHANNEL_MEMORY_HPP */
