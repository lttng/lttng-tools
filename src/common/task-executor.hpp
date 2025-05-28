/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-only
 */

#ifndef LTTNG_SCHEDULING_TASK_EXECUTOR_HPP
#define LTTNG_SCHEDULING_TASK_EXECUTOR_HPP

#include <common/eventfd.hpp>
#include <common/poller.hpp>
#include <common/scheduler.hpp>
#include <common/timerfd.hpp>
#include <common/waiter.hpp>

#include <atomic>
#include <thread>
#include <unistd.h>

namespace lttng {
namespace scheduling {
class task_executor final {
public:
	explicit task_executor(scheduler& scheduler);
	~task_executor();

	task_executor(const task_executor&) = delete;
	task_executor& operator=(const task_executor&) = delete;
	task_executor(task_executor&&) = delete;
	task_executor& operator=(task_executor&&) = delete;

	/* Signal the thread to stop and join it. */
	void stop();

private:
	void _run() noexcept;

	/* Wake up the thread (e.g., when a new task is scheduled) */
	void _wake() noexcept;

	std::thread _thread;
	scheduler& _scheduler;
	std::atomic<bool> _is_active{ false };
	lttng::eventfd _wake_eventfd;
	lttng::timerfd _wake_timerfd;
	lttng::poller _poller;
	lttng::synchro::waiter _launch_waiter;
};
} /* namespace scheduling */
} /* namespace lttng */

#endif /* LTTNG_SCHEDULING_TASK_EXECUTOR_HPP */