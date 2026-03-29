/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SESSIOND_APPLICATION_MANAGEMENT_THREAD_H
#define SESSIOND_APPLICATION_MANAGEMENT_THREAD_H

#include "lttng-sessiond.hpp"

#include <common/command-queue.hpp>

#include <cstdint>
#include <stdbool.h>

struct ust_app;

namespace lttng {
namespace sessiond {
namespace app_management {

enum class command_type : std::uint8_t {
	UNREGISTER_AND_DESTROY_APP,
};

struct command : public lttng::command_base {
	command(command_type type_, ust_app& app_) noexcept : type(type_), app(&app_)
	{
	}

	~command() override = default;

	command(command&&) noexcept = default;
	command& operator=(command&&) noexcept = default;
	command(const command&) = delete;
	command& operator=(const command&) = delete;

	command_type type;
	ust_app *app = nullptr;
};

} /* namespace app_management */
} /* namespace sessiond */
} /* namespace lttng */

bool launch_application_management_thread(
	int apps_cmd_pipe_read_fd,
	lttng::command_queue<lttng::sessiond::app_management::command>& unregistration_queue);

#endif /* SESSIOND_APPLICATION_MANAGEMENT_THREAD_H */
