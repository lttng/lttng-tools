/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CMD_GET_CHANNEL_MEMORY_USAGE_HPP
#define LTTNG_SESSIOND_CMD_GET_CHANNEL_MEMORY_USAGE_HPP

#include <common/string-utils/c-string-view.hpp>

#include <bin/lttng-sessiond/channel-memory-types.hpp>
#include <bin/lttng-sessiond/domain.hpp>
#include <bin/lttng-sessiond/session.hpp>
#include <vector>

namespace lttng {
namespace sessiond {
namespace commands {

std::vector<stream_memory_usage_group>
get_channel_memory_usage(const ltt_session::locked_ref& session,
			 lttng::domain_class domain,
			 lttng::c_string_view channel_name);

} /* namespace commands */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_CMD_GET_CHANNEL_MEMORY_USAGE_HPP */
