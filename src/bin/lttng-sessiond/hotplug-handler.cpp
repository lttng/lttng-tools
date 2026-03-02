/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "health-sessiond.hpp"
#include "hotplug-handler.hpp"
#include "modules-domain-orchestrator.hpp"
#include "session.hpp"
#include "thread.hpp"

#include <common/error.hpp>
#include <common/poller.hpp>

#include <unordered_map>

namespace ls = lttng::sessiond;
namespace lhh = ls::hotplug_handler;

namespace {

struct tracked_stream_group {
	ls::modules::stream_group *stream_group;
	ltt_session::id_t session_id;
};

struct thread_context {
	lttng::command_queue<lhh::command>& queue;
};

void process_commands(lttng::command_queue<lhh::command>& queue,
		      lttng::poller& poller,
		      std::unordered_map<int, tracked_stream_group>& tracked_stream_groups,
		      bool& quit_requested)
{
	while (auto cmd = queue.pop()) {
		switch (cmd->type) {
		case lhh::command_type::ADD_STREAM_GROUP:
		{
			LTTNG_ASSERT(cmd->stream_group);
			const auto stream_group_fd = cmd->stream_group->tracer_handle().fd();

			DBG_FMT("Hotplug handler: tracking stream group for hotplug: fd={}, session_id={}",
				stream_group_fd,
				cmd->session_id);

			tracked_stream_groups[stream_group_fd] = { cmd->stream_group,
								   cmd->session_id };

			poller.add(
				cmd->stream_group->tracer_handle(),
				lttng::poller::event_type::READABLE,
				[stream_group_fd,
				 &tracked_stream_groups](lttng::poller::event_type events) {
					if ((events & lttng::poller::event_type::READABLE) !=
					    lttng::poller::event_type::READABLE) {
						/*
						 * Error or hangup on the stream group fd.
						 * The orchestrator's destructor will send a
						 * REMOVE_STREAM_GROUP command to clean this up.
						 */
						WARN_FMT(
							"Hotplug handler: unexpected event on stream group fd: fd={}, events='{}'",
							stream_group_fd,
							events);
						return;
					}

					const auto it = tracked_stream_groups.find(stream_group_fd);
					LTTNG_ASSERT(it != tracked_stream_groups.end());

					const auto& tracked_stream_group = it->second;

					DBG_FMT("Hotplug handler: hotplug event on stream group: fd={}, session_id={}",
						stream_group_fd,
						tracked_stream_group.session_id);

					try {
						auto list_lock = ls::lock_session_list();
						auto session = ltt_session::find_locked_session(
							tracked_stream_group.session_id);

						session->get_kernel_orchestrator()
							.handle_stream_group_hotplug(
								*tracked_stream_group.stream_group);
					} catch (const lttng::sessiond::exceptions::
							 session_not_found_error&) {
						ERR_FMT("Hotplug handler: session not found during hotplug: session_id={}",
							tracked_stream_group.session_id);
						std::abort();
					}
				});

			cmd->_complete();
			break;
		}
		case lhh::command_type::REMOVE_STREAM_GROUP:
		{
			LTTNG_ASSERT(cmd->stream_group);
			const auto stream_group_fd = cmd->stream_group->tracer_handle().fd();

			DBG_FMT("Hotplug handler: untracking stream group: fd={}", stream_group_fd);

			const auto it = tracked_stream_groups.find(stream_group_fd);
			LTTNG_ASSERT(it != tracked_stream_groups.end());

			poller.remove(cmd->stream_group->tracer_handle());
			tracked_stream_groups.erase(it);

			cmd->_complete();
			break;
		}
		case lhh::command_type::QUIT:
			DBG("Hotplug handler: quit command received");
			quit_requested = true;
			cmd->_complete();
			return;
		}
	}
}

void *thread_hotplug_handler(void *data)
{
	auto *ctx = static_cast<thread_context *>(data);
	auto& queue = ctx->queue;

	DBG("Hotplug handler thread started");

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_KERNEL);
	health_code_update();

	lttng::poller poller;
	std::unordered_map<int, tracked_stream_group> tracked_stream_groups;
	bool quit_requested = false;

	poller.add(queue.wake_fd(),
		   lttng::poller::event_type::READABLE,
		   [&queue, &poller, &tracked_stream_groups, &quit_requested](
			   lttng::poller::event_type) {
			   process_commands(queue, poller, tracked_stream_groups, quit_requested);
		   });

	while (!quit_requested) {
		health_code_update();

		DBG("Hotplug handler thread polling");
		health_poll_entry();
		poller.poll(lttng::poller::timeout_type::WAIT_FOREVER);
		health_poll_exit();

		health_code_update();
	}

	health_unregister(the_health_sessiond);
	DBG("Hotplug handler thread exiting");
	return nullptr;
}

bool shutdown_hotplug_handler_thread(void *data)
{
	auto *ctx = static_cast<thread_context *>(data);

	lhh::command quit_cmd(lhh::command_type::QUIT);
	ctx->queue.send(std::move(quit_cmd));
	return true;
}

void cleanup_hotplug_handler_thread(void *data)
{
	delete static_cast<thread_context *>(data);
}

} /* namespace */

bool lhh::launch_hotplug_handler_thread(lttng::command_queue<lhh::command>& queue)
{
	auto *ctx = new (std::nothrow) thread_context{ queue };
	if (!ctx) {
		return false;
	}

	auto *thread = lttng_thread_create("Hotplug handler",
					   thread_hotplug_handler,
					   shutdown_hotplug_handler_thread,
					   cleanup_hotplug_handler_thread,
					   ctx);
	if (!thread) {
		delete ctx;
		return false;
	}

	lttng_thread_put(thread);
	return true;
}
