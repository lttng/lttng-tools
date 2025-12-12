/*
 * SPDX-License-Identifier: LGPL-2.0-only
 *
 * Uses heap management code adapted from Babeltrace 2's prio-heap.c.
 *
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#ifndef LTTNG_SCHEDULING_SCHEDULER_HPP
#define LTTNG_SCHEDULING_SCHEDULER_HPP

#include <common/error.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>

#include <vendor/optional.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <stddef.h>
#include <stdint.h>
#include <vector>

namespace lttng {
namespace scheduling {

using absolute_time = std::chrono::time_point<std::chrono::steady_clock, std::chrono::nanoseconds>;
using duration_ns = std::chrono::nanoseconds;

class scheduler;

class task {
	friend class scheduler;

public:
	using sptr = std::shared_ptr<task>;

	/*
	 * gcc 4.8.5 can't generate a default constructor that is noexcept.
	 * Hence, a trivial one is provided here.
	 * NOLINTBEGIN (modernize-use-equals-default)
	 */
	task() noexcept
	{
	}
	/* NOLINTEND (modernize-use-equals-default) */

	explicit task(std::string name) noexcept : _name(std::move(name))
	{
		LTTNG_ASSERT(!_name.empty());
	}

	/* Deactivate copy and assignment. */
	task(const task&) = delete;
	task(task&&) = delete;
	task& operator=(const task&) = delete;
	task& operator=(task&&) = delete;
	virtual ~task() = default;

	void run(absolute_time current_time) noexcept
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		if (_canceled) {
			/* Task is killed, do not run it. */
			return;
		}

		_run(current_time);
	}

	/*
	 * Indicate that this task should no longer be scheduled after the current execution.
	 * When this returns, the caller is guaranteed that the task is not running and that it will
	 * not be run in the future.
	 */
	void cancel() noexcept
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		_canceled = true;

		/*
		 * _next_scheduled_time is left unchanged since the task may still be in the
		 * scheduler's heap.
		 */
	}

	bool canceled() const noexcept
	{
		const std::lock_guard<std::mutex> lock(_mutex);
		return _canceled;
	}

protected:
	virtual void _run(absolute_time current_time) noexcept = 0;

	mutable std::mutex _mutex;
	bool _canceled = false;

private:
	virtual bool _must_be_rescheduled() const noexcept
	{
		/* A "once" task is not rescheduled once it has run. */
		return false;
	}

	absolute_time _get_next_scheduled_time() const noexcept
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		LTTNG_ASSERT(_next_scheduled_time.has_value());
		return *_next_scheduled_time;
	}

	void _set_next_scheduled_time(absolute_time next_time) noexcept
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		_next_scheduled_time = next_time;
	}

	/*
	 * nullopt means not scheduled.
	 *
	 * Don't access directly, use _get_next_scheduled_time() and
	 * _set_next_scheduled_time() to ensure proper locking.
	 */
	nonstd::optional<absolute_time> _next_scheduled_time;

	const std::string _name{ "Anonymous" };
};

class periodic_task : public task {
	friend class scheduler;

public:
	using sptr = std::shared_ptr<periodic_task>;

	/*
	 * Periodic task are automatically rescheduled following their period.
	 * Note that the scheduler cannot guarantee the deadlines are honored.
	 * As such, a task that couldn't be run at its set period will only run
	 * once even if the period was exceeded multiple times.
	 *
	 * A periodic task will also be re-queued at current_time + period
	 * which can cause the timing of tasks to "drift" when deadlines are
	 * not honored. If a task needs to be invoked at a precise time, use
	 * a regular task and enqueue it manually by providing a relative time
	 * as the deadline.
	 */
	explicit periodic_task(duration_ns period) noexcept : _period_ns{ period }
	{
	}

	periodic_task(duration_ns period, std::string name) noexcept :
		task(std::move(name)), _period_ns{ period }
	{
	}

	/* Deactivate copy and assignment. */
	periodic_task(const periodic_task&) = delete;
	periodic_task(periodic_task&&) = delete;
	periodic_task& operator=(const periodic_task&) = delete;
	periodic_task& operator=(periodic_task&&) = delete;
	~periodic_task() override = default;

	duration_ns period() const noexcept
	{
		return _period_ns;
	}

protected:
	/*
	 * This method is used by periodic tasks to cancel themselves when they have run
	 * enough times.
	 */
	void _cancel_no_lock()
	{
		_canceled = true;
	}

private:
	bool _must_be_rescheduled() const noexcept override
	{
		const std::lock_guard<std::mutex> lock(_mutex);
		return !_canceled;
	}

	const duration_ns _period_ns;
};

class scheduler final {
public:
	using task_scheduled_callback = std::function<void(absolute_time)>;

	/*
	 * gcc 4.8.5 can't generate a default constructor that is noexcept.
	 * Hence, a trivial one is provided here.
	 * NOLINTBEGIN (modernize-use-equals-default)
	 */
	scheduler() noexcept {};
	/* NOLINTEND (modernize-use-equals-default) */
	~scheduler() = default;

	/* Deactivate copy and assignment. */
	scheduler(const scheduler&) = delete;
	scheduler(scheduler&&) = delete;
	scheduler& operator=(const scheduler&) = delete;
	scheduler& operator=(scheduler&&) = delete;

	/* Schedule a "once" or periodic task in the future. */
	void schedule(task::sptr task, absolute_time when_to_run = std::chrono::steady_clock::now())
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		for (const auto& callback : _task_scheduled_callbacks) {
			callback(when_to_run);
		}

		task->_set_next_scheduled_time(when_to_run);
		_task_heap.insert(std::move(task));
	}

	/*
	 * Run scheduled tasks that have expired as of the current time.
	 *
	 * Returns:
	 * - The number of nanoseconds until the next task, if one is still scheduled.
	 * - `nonstd::nullopt` if no tasks are currently scheduled.
	 */
	nonstd::optional<duration_ns>
	tick(absolute_time current_time = std::chrono::steady_clock::now()) noexcept
	{
		_last_tick = current_time;

		while (true) {
			lttng::scheduling::task::sptr task_to_run = nullptr;

			{
				const std::lock_guard<std::mutex> lock(_mutex);

				const auto candidate = _task_heap.peek();

				/* If the task heap is empty, return no next task. */
				if (candidate == nullptr) {
					return nonstd::nullopt;
				}

				if (candidate->_get_next_scheduled_time() > _last_tick) {
					return candidate->_get_next_scheduled_time() - current_time;
				}

				/* The task is ready to run. */
				task_to_run = _task_heap.pop();
			}

			/*
			 * The scheduler lock doesn't need to be held while the task is being run.
			 */

			const auto time_before_task_run = std::chrono::steady_clock::now();
			DBG_FMT("Running task: name=`{}`", task_to_run->_name);

			_run_task(std::move(task_to_run));

			DBG_FMT("Task completed: duration={}",
				std::chrono::steady_clock::now() - time_before_task_run);
		}
	}

	void add_task_scheduled_callback(task_scheduled_callback callback) noexcept
	{
		const std::lock_guard<std::mutex> lock(_mutex);
		_task_scheduled_callbacks.push_back(std::move(callback));
	}

private:
	/* Run a task and reschedule it, if necessary. */
	void _run_task(task::sptr task) noexcept
	{
		task->run(_last_tick);
		if (task->_must_be_rescheduled()) {
			auto& periodic_task_to_schedule = static_cast<periodic_task&>(*task);

			schedule(std::move(task), _last_tick + periodic_task_to_schedule.period());
		}
	}

	class task_heap {
	public:
		/* Insert task to schedule. */
		void insert(task::sptr new_task)
		{
			/* Position starts at the last element. */
			auto position = _tasks.size();

			_tasks.resize(_tasks.size() + 1);

			while (position > 0 &&
			       _task_should_run_before(*new_task, *_tasks[_parent(position)])) {
				/* Move parent down until we find the right spot. */
				_tasks[position] = std::move(_tasks[_parent(position)]);
				position = _parent(position);
			}

			_tasks[position] = std::move(new_task);
		}

		/* Peek at task with the nearest deadline. */
		task *peek() const noexcept
		{
			return _tasks.empty() ? nullptr : _tasks.begin()->get();
		}

		/* Pop task with the nearest deadline. */
		task::sptr pop() noexcept
		{
			switch (_tasks.size()) {
			case 0:
				return nullptr;
			case 1:
				auto task = std::move(*_tasks.begin());

				_tasks.clear();
				return task;
			}

			auto task = std::move(*_tasks.begin());
			*_tasks.begin() = std::move(*(_tasks.end() - 1));
			_tasks.resize(_tasks.size() - 1);
			heapify(0);

			return task;
		}

	private:
		/* Heap internals. */
		size_t _parent(const size_t i) const noexcept
		{
			return (i - 1) >> 1;
		}

		size_t _left(const size_t i) const noexcept
		{
			return (i << 1) + 1;
		}

		size_t _right(const size_t i) const noexcept
		{
			return (i << 1) + 2;
		}

		bool _task_should_run_before(const task& a, const task& b) const noexcept
		{
			return a._get_next_scheduled_time() < b._get_next_scheduled_time();
		}

		void heapify(size_t i) noexcept
		{
			for (;;) {
				const auto left_idx = _left(i);
				const auto right_idx = _right(i);
				size_t highest_prio_idx;

				if (left_idx < _tasks.size() &&
				    _task_should_run_before(*_tasks[left_idx], *_tasks[i])) {
					highest_prio_idx = left_idx;
				} else {
					highest_prio_idx = i;
				}

				if (right_idx < _tasks.size() &&
				    _task_should_run_before(*_tasks[right_idx],
							    *_tasks[highest_prio_idx])) {
					highest_prio_idx = right_idx;
				}

				if (highest_prio_idx == i) {
					break;
				}

				std::swap(_tasks[i], _tasks[highest_prio_idx]);
				i = highest_prio_idx;
			}
		}

		std::vector<task::sptr> _tasks;
	} _task_heap;

	/* Initialized to epoch. */
	absolute_time _last_tick;
	std::mutex _mutex;
	std::vector<task_scheduled_callback> _task_scheduled_callbacks;
};

} /* namespace scheduling */
} /* namespace lttng */

#endif /* LTTNG_SCHEDULING_SCHEDULER_HPP */
