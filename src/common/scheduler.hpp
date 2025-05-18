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

#include <stddef.h>
#include <stdint.h>

namespace lttng {
namespace scheduling {

using absolute_time_ms = uint64_t;
using relative_time_ms = uint64_t;

template <unsigned int>
class scheduler;

class task {
	template <unsigned int>
	friend class scheduler;

public:
	/*
	 * gcc 4.8.5 can't generate a default constructor that is noexcept.
	 * Hence, a trivial one is provided here.
	 * NOLINTBEGIN (modernize-use-equals-default)
	 */
	task() noexcept
	{
	}
	/* NOLINTEND (modernize-use-equals-default) */

	/* Deactivate copy and assignment. */
	task(const task&) = delete;
	task(task&&) = delete;
	task& operator=(const task&) = delete;
	task& operator=(task&&) = delete;
	virtual ~task() = default;

	virtual void run(absolute_time_ms current_time) noexcept = 0;
	bool scheduled() const noexcept
	{
		return _next_scheduled_time;
	}

private:
	virtual bool must_be_rescheduled() const noexcept
	{
		/* A "once" task is not rescheduled once it has run. */
		return false;
	}

	/* 0 means not scheduled. */
	absolute_time_ms _next_scheduled_time = 0;
};

class periodic_task : public task {
	template <unsigned int>
	friend class scheduler;

public:
	/*
	 * Periodic task are automatically rescheduled following their period.
	 * Note that the scheduler cannot guarantee the deadlines are honored.
	 * As such, a task that couldn't be run at its set period will only run
	 * once even if the period was exceeded multiple times.
	 *
	 * A periodic task will also be re-queued at current_time + period_ms
	 * which can cause the timing of tasks to "drift" when deadlines are
	 * not honored. If a task needs to be invoked at a precise time, use
	 * a regular task and enqueue it manually by providing a relative time
	 * as the deadline.
	 */
	explicit periodic_task(relative_time_ms period_ms) noexcept :
		_period_ms{ period_ms }, _killed{ false }
	{
	}

	/* Deactivate copy and assignment. */
	periodic_task(const periodic_task&) = delete;
	periodic_task(periodic_task&&) = delete;
	periodic_task& operator=(const periodic_task&) = delete;
	periodic_task& operator=(periodic_task&&) = delete;
	~periodic_task() = default;

	relative_time_ms period_ms() const noexcept
	{
		return _period_ms;
	}

	/* Indicate that this task should no longer be scheduled after the current execution. */
	void kill() noexcept
	{
		_killed = true;
	}

	void revive() noexcept
	{
		_killed = false;
	}

	/* Effective at the end of the next tick. */
	void period_ms(relative_time_ms new_period) noexcept
	{
		_period_ms = new_period;
	}

private:
	bool must_be_rescheduled() const noexcept override
	{
		return !_killed;
	}

	relative_time_ms _period_ms:15;
	bool _killed:1;
};

template <unsigned int max_scheduled_tasks>
class scheduler final {
public:
	scheduler() noexcept = default;
	~scheduler() = default;

	/* Deactivate copy and assignment. */
	scheduler(const scheduler&) = delete;
	scheduler(scheduler&&) = delete;
	scheduler& operator=(const scheduler&) = delete;
	scheduler& operator=(scheduler&&) = delete;

	/* Schedule a "once" or periodic task in the future. */
	void schedule_task(task& task, relative_time_ms in_how_many_ms = 0) noexcept
	{
		task._next_scheduled_time = _last_tick_ms + in_how_many_ms;
		_task_heap.insert(task);
	}

	/*
	 * Returns how many milliseconds can elapse before the next tick invocation,
	 * allowing the thread to sleep when the next task is sufficiently far away.
	 */
	relative_time_ms tick(absolute_time_ms current_time_ms) noexcept
	{
		_last_tick_ms = current_time_ms;

		while (true) {
			auto *task = _task_heap.peek();

			if (!task) {
				/* No task left to run... Rest in peace. */
				return UINT16_MAX;
			}

			if (task->_next_scheduled_time <= _last_tick_ms) {
				run_task(*_task_heap.pop());
			} else {
				return task->_next_scheduled_time - current_time_ms;
			}
		}
	}

private:
	/* Run a task and reschedule it if necessary. */
	void run_task(task& task) noexcept
	{
		task.run(_last_tick_ms);
		if (task.must_be_rescheduled()) {
			auto& task_to_schedule = static_cast<periodic_task&>(task);

			schedule_task(task_to_schedule, task_to_schedule.period_ms());
		} else {
			task._next_scheduled_time = 0;
		}
	}

	class task_heap {
	public:
		/* Insert task to schedule. */
		void insert(task& new_task) noexcept
		{
			if (_scheduled_task_count >= max_scheduled_tasks) {
				/* Internal error, should panic. */
				return;
			}

			auto pos = _scheduled_task_count;
			_scheduled_task_count++;

			while (pos > 0 &&
			       _task_should_run_before(new_task, *_tasks[_parent(pos)])) {
				/* Move parent down until we find the right spot. */
				_tasks[pos] = _tasks[_parent(pos)];
				pos = _parent(pos);
			}

			_tasks[pos] = &new_task;
		}

		/* Peek at task with the nearest deadline. */
		task *peek() const noexcept
		{
			if (_scheduled_task_count != 0) {
				return _tasks[0];
			} else {
				return nullptr;
			}
		}

		/* Pop task with the nearest deadline. */
		task *pop() noexcept
		{
			switch (_scheduled_task_count) {
			case 0:
				return nullptr;
			case 1:
				_scheduled_task_count = 0;
				return _tasks[0];
			}

			_scheduled_task_count--;
			const auto res = _tasks[0];
			_tasks[0] = _tasks[_scheduled_task_count];
			heapify(0);

			return res;
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
			return a._next_scheduled_time < b._next_scheduled_time;
		}

		void heapify(size_t i) noexcept
		{
			for (;;) {
				const auto left_idx = _left(i);
				const auto right_idx = _right(i);
				size_t highest_prio_idx;

				if (left_idx < _scheduled_task_count &&
				    _task_should_run_before(*_tasks[left_idx], *_tasks[i])) {
					highest_prio_idx = left_idx;
				} else {
					highest_prio_idx = i;
				}

				if (right_idx < _scheduled_task_count &&
				    _task_should_run_before(*_tasks[right_idx],
							    *_tasks[highest_prio_idx])) {
					highest_prio_idx = right_idx;
				}

				if (highest_prio_idx == i) {
					break;
				}

				const auto tmp = _tasks[i];
				_tasks[i] = _tasks[highest_prio_idx];
				_tasks[highest_prio_idx] = tmp;
				i = highest_prio_idx;
			}
		}

		unsigned int _scheduled_task_count = 0;
		task *_tasks[max_scheduled_tasks] = {};
	} _task_heap;
	absolute_time_ms _last_tick_ms = 0;
};

} /* namespace scheduling */
} /* namespace lttng */

#endif /* LTTNG_SCHEDULING_SCHEDULER_HPP */
