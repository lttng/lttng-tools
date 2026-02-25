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

struct tracked_channel {
	ls::modules::stream_group *channel;
	ltt_session::id_t session_id;
};

struct thread_context {
	lttng::command_queue<lhh::command>& queue;
};

void process_commands(lttng::command_queue<lhh::command>& queue,
		      lttng::poller& poller,
		      std::unordered_map<int, tracked_channel>& tracked_channels,
		      bool& quit_requested)
{
	while (auto cmd = queue.pop()) {
		switch (cmd->type) {
		case lhh::command_type::ADD_CHANNEL:
		{
			LTTNG_ASSERT(cmd->channel);
			const auto channel_fd = cmd->channel->tracer_handle().fd();

			DBG_FMT("Hotplug handler: tracking channel for hotplug: fd={}, session_id={}",
				channel_fd,
				cmd->session_id);

			tracked_channels[channel_fd] = { cmd->channel, cmd->session_id };

			poller.add(
				cmd->channel->tracer_handle(),
				lttng::poller::event_type::READABLE,
				[channel_fd, &tracked_channels](lttng::poller::event_type events) {
					if ((events & lttng::poller::event_type::READABLE) !=
					    lttng::poller::event_type::READABLE) {
						/*
						 * Error or hangup on the channel fd.
						 * The orchestrator's destructor will send a
						 * REMOVE_CHANNEL command to clean this up.
						 */
						WARN_FMT(
							"Hotplug handler: unexpected event on channel fd: fd={}, events='{}'",
							channel_fd,
							events);
						return;
					}

					const auto it = tracked_channels.find(channel_fd);
					LTTNG_ASSERT(it != tracked_channels.end());

					const auto& channel = it->second;

					DBG_FMT("Hotplug handler: hotplug event on channel: fd={}, session_id={}",
						channel_fd,
						channel.session_id);

					try {
						auto list_lock = ls::lock_session_list();
						auto session = ltt_session::find_locked_session(
							channel.session_id);

						session->get_kernel_orchestrator()
							.handle_channel_hotplug(*channel.channel);
					} catch (const lttng::sessiond::exceptions::
							 session_not_found_error&) {
						ERR_FMT("Hotplug handler: session not found during hotplug: session_id={}",
							channel.session_id);
						std::abort();
					}
				});

			cmd->_complete();
			break;
		}
		case lhh::command_type::REMOVE_CHANNEL:
		{
			LTTNG_ASSERT(cmd->channel);
			const auto channel_fd = cmd->channel->tracer_handle().fd();

			DBG_FMT("Hotplug handler: untracking channel: fd={}", channel_fd);

			const auto it = tracked_channels.find(channel_fd);
			LTTNG_ASSERT(it != tracked_channels.end());

			poller.remove(cmd->channel->tracer_handle());
			tracked_channels.erase(it);

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
	std::unordered_map<int, tracked_channel> tracked_channels;
	bool quit_requested = false;

	poller.add(
		queue.wake_fd(),
		lttng::poller::event_type::READABLE,
		[&queue, &poller, &tracked_channels, &quit_requested](lttng::poller::event_type) {
			process_commands(queue, poller, tracked_channels, quit_requested);
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
