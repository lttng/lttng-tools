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

#include <bin/lttng-sessiond/channel-memory-types.hpp>
#include <bin/lttng-sessiond/domain.hpp>
#include <bin/lttng-sessiond/session.hpp>
#include <chrono>

namespace lttng {
namespace sessiond {
namespace commands {

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

#endif /* LTTNG_SESSIOND_CMD_RECLAIM_CHANNEL_MEMORY_HPP */
