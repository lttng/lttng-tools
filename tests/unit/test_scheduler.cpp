/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#include <common/make-unique.hpp>
#include <common/scheduler.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <random>
#include <tap/tap.h>
#include <vector>

namespace {
namespace once_scheduling {

class task_once : public lttng::scheduling::task {
public:
	explicit task_once(bool& value_to_set) : _task_was_scheduled{ value_to_set }
	{
	}

	void
	run([[maybe_unused]] lttng::scheduling::absolute_time_ms current_time) noexcept override
	{
		/* Indicate that task executed. */
		_task_was_scheduled = true;
	}

private:
	bool& _task_was_scheduled;
};

void test_task_not_ran_immediately()
{
	lttng::scheduling::scheduler scheduler;
	bool task_ran = false;

	scheduler.tick(1);
	task_once my_task(task_ran);

	/*
	 * The task is scheduled to run on the next tick (ideally started right after this tick
	 * completes).
	 */
	scheduler.schedule_task(my_task);
	ok(task_ran == false, "Task scheduled \"now\" didn't run during scheduling");

	/* Next tick occurs "immediately". */
	scheduler.tick(1);
	ok(task_ran == true, "Task scheduled \"now\" ran at the next tick");
}

void test_task_not_ran_directly_when_scheduling()
{
	lttng::scheduling::scheduler scheduler;
	bool task_ran = false;

	scheduler.tick(1);
	task_once my_task(task_ran);

	/* The task should only run in 100ms, so for tick >= 101. */
	scheduler.schedule_task(my_task, 100);
	ok(task_ran == false, "Task scheduled @ 101 not ran right after scheduling");
}

void test_task_not_ran_before_deadline()
{
	lttng::scheduling::scheduler scheduler;
	bool task_ran = false;

	scheduler.tick(1);
	task_once my_task(task_ran);

	/* The task should only run in 100ms, so for ticks >= 101. */
	scheduler.schedule_task(my_task, 100);
	scheduler.tick(10);
	ok(task_ran == false, "Task scheduled @ 101 not ran after tick @ 10");
}

void test_task_ran_on_deadline()
{
	lttng::scheduling::scheduler scheduler;
	bool task_ran = false;

	scheduler.tick(1);
	task_once my_task(task_ran);

	/* The task should only run in 100ms, so for ticks >= 101. */
	scheduler.schedule_task(my_task, 100);

	const auto tick_ret = scheduler.tick(101);
	ok(task_ran == true, "Task scheduled @ 101 ran after tick @ 101");

	ok(!tick_ret.has_value(), "Tick @ 101 returned no time until next task");
}

void test_task_ran_on_late_tick()
{
	lttng::scheduling::scheduler scheduler;
	bool task_ran = false;

	scheduler.tick(1);
	task_once my_task(task_ran);

	/* The task should only run in 100ms, so for ticks >= 101. */
	scheduler.schedule_task(my_task, 100);
	scheduler.tick(200);
	ok(task_ran == true, "Task scheduled @ 101 ran after tick @ 200");
}

void test_task_not_ran_twice()
{
	lttng::scheduling::scheduler scheduler;
	bool task_ran = false;

	scheduler.tick(1);
	task_once my_task(task_ran);

	/* The task should only run in 100ms, so for ticks >= 101. */
	scheduler.schedule_task(my_task, 100);
	scheduler.tick(200);
	ok(task_ran, "Task scheduled @ 100 ran after tick @ 200");

	/*
	 * Reset "ran" state to validate that a task that was scheduled to run only once
	 * is not ran twice.
	 */
	task_ran = false;
	scheduler.tick(500);
	ok(task_ran == false, "Task scheduled @ 101, and already ran, does not run twice");
}

void test_tasks_all_ran_after_deadline()
{
	lttng::scheduling::scheduler scheduler;
	bool task_50_ran = false, task_100_ran = false, task_150_ran = false;

	task_once task_50(task_50_ran);
	task_once task_100(task_100_ran);
	task_once task_150(task_150_ran);

	/* The task should only run in 100ms, so for ticks >= 101. */
	scheduler.schedule_task(task_150, 150);
	scheduler.schedule_task(task_50, 50);
	scheduler.schedule_task(task_100, 100);
	scheduler.tick(200);

	ok(task_50_ran == true, "Task scheduled @ 50 ran after tick @ 200");
	ok(task_100_ran == true, "Task scheduled @ 100 ran after tick @ 200");
	ok(task_150_ran == true, "Task scheduled @ 150 ran after tick @ 200");
}

void test_tasks_some_ran_after_tick()
{
	lttng::scheduling::scheduler scheduler;
	bool task_50_ran = false, task_100_ran = false, task_150_ran = false;

	task_once task_50(task_50_ran);
	task_once task_100(task_100_ran);
	task_once task_150(task_150_ran);

	/* The task should only run in 100ms, so for ticks >= 101. */
	scheduler.schedule_task(task_150, 150);
	scheduler.schedule_task(task_50, 50);
	scheduler.schedule_task(task_100, 100);
	scheduler.tick(120);

	ok(task_50_ran == true, "Task scheduled @ 50 ran after tick @ 120");
	ok(task_100_ran == true, "Task scheduled @ 100 ran after tick @ 120");
	ok(task_150_ran == false, "Task scheduled @ 150 didn't run after tick @ 120");
}

void test_lots_of_tasks_ran_in_order()
{
	lttng::scheduling::scheduler scheduler;
	std::array<bool, 16> tasks_ran = { false };
	std::vector<std::pair<std::unique_ptr<task_once>, lttng::scheduling::relative_time_ms>>
		tasks;

	/* Create tasks to be scheduled at ticks 5, 15, 25, 35, etc. */
	for (unsigned int i = 0; i < tasks_ran.size(); i++) {
		tasks.emplace_back(lttng::make_unique<task_once>(tasks_ran[i]), (i * 10) + 5);
	}

	/*
	 * Shuffle tasks to insert them in a random order in the scheduler's set of tasks.
	 * The tasks_ran array remains in order of scheduled tasks to validate the order
	 * of the execution of the tasks.
	 */
	std::shuffle(std::begin(tasks), std::end(tasks), std::default_random_engine{});

	for (const auto& task_pair : tasks) {
		scheduler.schedule_task(*task_pair.first, task_pair.second);
	}

	for (unsigned int i = 0; i < tasks_ran.size() + 1; i++) {
		const auto current_tick = i * 10;

		scheduler.tick(current_tick);

		unsigned int consecutive_tasks_executed = 0;
		for (const auto& ran : tasks_ran) {
			if (ran) {
				consecutive_tasks_executed++;
			} else {
				break;
			}
		}

		ok(i == consecutive_tasks_executed,
		   "%u first tasks executed as of tick %u",
		   i,
		   current_tick);
	}
}

} /* namespace once_scheduling */

namespace periodic_scheduling {

class periodic_task : public lttng::scheduling::periodic_task {
public:
	periodic_task(lttng::scheduling::relative_time_ms period_ms,
		      unsigned int& value_to_increment) :
		lttng::scheduling::periodic_task(period_ms),
		_value_to_increment{ value_to_increment }
	{
	}

	void
	run([[maybe_unused]] lttng::scheduling::absolute_time_ms current_time) noexcept override
	{
		/* Indicate that task ran. */
		_value_to_increment++;
	}

private:
	unsigned int& _value_to_increment;
};

class periodic_task_die_after_3 : public lttng::scheduling::periodic_task {
public:
	periodic_task_die_after_3(lttng::scheduling::relative_time_ms period_ms,
				  unsigned int& value_to_increment) :
		lttng::scheduling::periodic_task(period_ms),
		_value_to_increment{ value_to_increment }
	{
	}

	void
	run([[maybe_unused]] lttng::scheduling::absolute_time_ms current_time) noexcept override
	{
		/* Indicate that task ran. */
		_value_to_increment++;
		if (_value_to_increment == 3) {
			/* This task should no longer run. */
			kill();
		}
	}

private:
	unsigned int& _value_to_increment;
};

void test_task_not_ran_before_deadline()
{
	lttng::scheduling::scheduler scheduler;
	unsigned int task_run_count = 0;

	/* Run every 100 ms. */
	periodic_task my_task(100, task_run_count);

	/* The task should run every 100 ms, starting in 100 ms. */
	scheduler.schedule_task(my_task, my_task.period_ms());
	scheduler.tick(50);
	ok(task_run_count == 0, "Periodic task scheduled @ 100 not run with tick @ 50");
}

void test_task_ran_on_deadline()
{
	lttng::scheduling::scheduler scheduler;
	unsigned int task_run_count = 0;

	/* Run every 100 ms. */
	periodic_task my_task(100, task_run_count);

	/* The task should run every 100 ms, starting in 100 ms. */
	scheduler.schedule_task(my_task, my_task.period_ms());
	scheduler.tick(100);
	ok(task_run_count == 1, "Periodic task scheduled @ 100 ran during tick @ 100");
}

void test_task_second_run_not_before_deadline()
{
	lttng::scheduling::scheduler scheduler;
	unsigned int task_run_count = 0;

	/* Run every 100 ms. */
	periodic_task my_task(100, task_run_count);

	/* The task should run every 100 ms, starting in 100 ms. */
	scheduler.schedule_task(my_task, my_task.period_ms());
	scheduler.tick(120);
	ok(task_run_count == 1, "Periodic task scheduled @ 100 ran during tick @ 120");

	scheduler.tick(150);
	ok(task_run_count == 1, "Periodic task scheduled @ 200 didn't run twice with tick @ 150");
}

void test_task_rescheduled()
{
	lttng::scheduling::scheduler scheduler;
	unsigned int task_run_count = 0;

	/* Run every 100 ms. */
	periodic_task my_task(100, task_run_count);

	/* The task should run every 100 ms, starting in 100 ms. */
	scheduler.schedule_task(my_task, my_task.period_ms());
	const auto tick_ret = scheduler.tick(100);
	ok(task_run_count == 1, "Periodic task scheduled @ 100 ran during tick @ 100");
	ok(tick_ret.has_value() && tick_ret == 100, "Tick @ 100 returned time until next task");

	scheduler.tick(200);
	ok(task_run_count == 2, "Periodic task scheduled @ 200 ran during tick @ 200");
	scheduler.tick(300);
	ok(task_run_count == 3, "Periodic task scheduled @ 300 ran during tick @ 300");
}

void test_task_die()
{
	lttng::scheduling::scheduler scheduler;
	unsigned int task_run_count = 0;

	/* Run every 100 ms. */
	periodic_task_die_after_3 my_task(100, task_run_count);

	/* The task should run every 100 ms, starting in 100 ms. */
	scheduler.schedule_task(my_task, my_task.period_ms());
	scheduler.tick(100);
	ok(task_run_count == 1, "Periodic task scheduled @ 100 ran during tick @ 100");
	scheduler.tick(200);
	ok(task_run_count == 2, "Periodic task scheduled @ 200 ran during tick @ 200");
	scheduler.tick(300);
	ok(task_run_count == 3, "Periodic task scheduled @ 300 ran during tick @ 300");

	scheduler.tick(400);
	ok(task_run_count == 3,
	   "Periodic task scheduled to run only three times only ran three times");
}

} /* namespace periodic_scheduling */
} /* namespace */

int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
{
	plan_tests(44);

	once_scheduling::test_task_not_ran_immediately();
	once_scheduling::test_task_not_ran_before_deadline();
	once_scheduling::test_task_not_ran_directly_when_scheduling();
	once_scheduling::test_task_not_ran_twice();
	once_scheduling::test_task_ran_on_deadline();
	once_scheduling::test_task_ran_on_late_tick();
	once_scheduling::test_tasks_all_ran_after_deadline();
	once_scheduling::test_tasks_some_ran_after_tick();
	once_scheduling::test_lots_of_tasks_ran_in_order();

	periodic_scheduling::test_task_second_run_not_before_deadline();
	periodic_scheduling::test_task_not_ran_before_deadline();
	periodic_scheduling::test_task_ran_on_deadline();
	periodic_scheduling::test_task_rescheduled();
	periodic_scheduling::test_task_die();

	return exit_status();
}