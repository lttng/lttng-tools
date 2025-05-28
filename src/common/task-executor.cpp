/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-only
 */

#include <common/error.hpp>
#include <common/task-executor.hpp>

lttng::scheduling::task_executor::task_executor(scheduler& scheduler) :
	_scheduler(scheduler), _wake_eventfd(true)
{
	_scheduler.add_task_scheduled_callback(
		[this](lttng::scheduling::absolute_time next_task_time [[maybe_unused]]) {
			/* Wake-up to re-evaluate the nearest deadline. */
			_wake();
		});

	/*
	 * The eventfd is used to wake the scheduler thread when the timer needs
	 * to be reevaluated (e.g., when a new task is scheduled) or when the
	 * thread needs to be stopped.
	 */
	_poller.add(_wake_eventfd,
		    lttng::poller::event_type::READABLE,
		    [this](lttng::poller::event_type events) {
			    if (events == lttng::poller::event_type::READABLE) {
				    /* Disarm the eventfd. */
				    this->_wake_eventfd.decrement();
			    }
		    });

	/*
	 * The timerfd is used to wake the scheduler thread a task's deadline expires.
	 * It is initially unarmed, causing no spurious wake-ups, and will be armed when
	 * the first task is scheduled.
	 */
	_poller.add(_wake_timerfd,
		    lttng::poller::event_type::READABLE,
		    [this](lttng::poller::event_type events [[maybe_unused]]) {
			    if (events == lttng::poller::event_type::READABLE) {
				    /*
				     * Clear the "expiration" of the timer. Since the timerfd
				     * is not armed, it will not wake up the thread until a new task
				     * is scheduled.
				     */
				    _wake_timerfd.reset();
			    }
		    });

	_thread = std::thread(&task_executor::_run, this);
	_launch_waiter.wait();
}

lttng::scheduling::task_executor::~task_executor()
{
	if (_thread.joinable()) {
		stop();
	}
}

void lttng::scheduling::task_executor::_run() noexcept
{
	_is_active.store(true);
	_launch_waiter.get_waker().wake();

	while (_is_active.load()) {
		_poller.poll(lttng::poller::timeout_type::WAIT_FOREVER);

		const auto next_task_delay = _scheduler.tick(std::chrono::steady_clock::now());
		if (next_task_delay) {
			/* Arm the timerfd to wake up when the next task is due. */
			_wake_timerfd.settime(*next_task_delay);
		}
	}

	DBG_FMT("Task executor thread exiting");
}

void lttng::scheduling::task_executor::_wake() noexcept
{
	if (_thread.get_id() == std::this_thread::get_id()) {
		/* The thread is already running, no need to wake it up. */
		return;
	}

	/* Wake up the scheduler thread. */
	_wake_eventfd.increment();
}

void lttng::scheduling::task_executor::stop()
{
	_is_active.store(false);

	if (!_thread.joinable()) {
		/* The thread is not running, nothing to do. */
		return;
	}

	/* Wake the thread to make sure it sees it should exit. */
	_wake();
	_thread.join();
}
