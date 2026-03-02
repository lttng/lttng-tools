/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_HOTPLUG_HANDLER_HPP
#define LTTNG_SESSIOND_HOTPLUG_HANDLER_HPP

#include <common/command-queue.hpp>

#include <cstdint>

namespace lttng {
namespace sessiond {
namespace modules {
class stream_group;
} /* namespace modules */

namespace hotplug_handler {

enum class command_type : std::uint8_t {
	ADD_STREAM_GROUP,
	REMOVE_STREAM_GROUP,
	QUIT,
};

/* Session id type matching ltt_session::id_t. */
using session_id_t = std::uint64_t;

struct command : public lttng::command_base {
	explicit command(command_type type_) noexcept : type(type_)
	{
	}

	command(command_type type_,
		modules::stream_group& channel_,
		session_id_t session_id_) noexcept :
		type(type_), stream_group(&channel_), session_id(session_id_)
	{
	}

	~command() override = default;

	command(command&&) noexcept = default;
	command& operator=(command&&) noexcept = default;
	command(const command&) = delete;
	command& operator=(const command&) = delete;

	command_type type;
	modules::stream_group *stream_group = nullptr;
	session_id_t session_id = 0;
};

bool launch_hotplug_handler_thread(lttng::command_queue<command>& queue);

} /* namespace hotplug_handler */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_HOTPLUG_HANDLER_HPP */
