/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#include <common/eventfd.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>
#include <common/poller.hpp>
#include <common/timerfd.hpp>

#include <tap/tap.h>

/* For error.hpp */
int lttng_opt_quiet;
int lttng_opt_verbose;
int lttng_opt_mi;

namespace {

void test_event_fd_increment_decrement()
{
	lttng::eventfd event_fd;
	lttng::poller poller;

	lttng::poller::event_type reported_events = lttng::poller::event_type::NONE;
	poller.add(event_fd,
		   lttng::poller::event_type::READABLE,
		   [&reported_events](lttng::poller::event_type events) {
			   reported_events = events;
		   });
	poller.poll(lttng::poller::timeout_type::NO_WAIT);

	ok(reported_events == lttng::poller::event_type::NONE,
	   "Poller reports no pending events initially");

	event_fd.increment();
	poller.poll(lttng::poller::timeout_type::NO_WAIT);
	ok(reported_events == lttng::poller::event_type::READABLE,
	   "Eventfd is marked as readable after increment");

	event_fd.decrement();
	reported_events = lttng::poller::event_type::NONE;
	poller.poll(lttng::poller::timeout_type::NO_WAIT);
	ok(reported_events == (lttng::poller::event_type::NONE),
	   "Eventfd has no event after being decremented");
}

void test_multiple_fds()
{
	lttng::eventfd event_fd1, event_fd2;
	lttng::poller poller;

	lttng::poller::event_type events1 = lttng::poller::event_type::NONE;
	lttng::poller::event_type events2 = lttng::poller::event_type::NONE;

	poller.add(event_fd1,
		   lttng::poller::event_type::READABLE,
		   [&events1](lttng::poller::event_type e) { events1 = e; });
	poller.add(event_fd2,
		   lttng::poller::event_type::READABLE,
		   [&events2](lttng::poller::event_type e) { events2 = e; });

	event_fd1.increment();
	poller.poll(lttng::poller::timeout_type::NO_WAIT);
	ok(events1 == lttng::poller::event_type::READABLE, "First eventfd triggers its callback");
	ok(events2 == lttng::poller::event_type::NONE, "Second eventfd does not trigger");

	event_fd1.decrement();
	events1 = lttng::poller::event_type::NONE;
	event_fd2.increment();
	poller.poll(lttng::poller::timeout_type::NO_WAIT);
	ok(events2 == lttng::poller::event_type::READABLE, "Second eventfd triggers its callback");
	ok(events1 == lttng::poller::event_type::NONE, "First eventfd does not trigger again");
}

void test_modify_events()
{
	lttng::eventfd event_fd;
	lttng::poller poller;
	lttng::poller::event_type events = lttng::poller::event_type::NONE;

	poller.add(event_fd,
		   lttng::poller::event_type::READABLE,
		   [&events](lttng::poller::event_type e) { events = e; });
	poller.modify(event_fd, lttng::poller::event_type::NONE);
	event_fd.increment();
	poller.poll(lttng::poller::timeout_type::NO_WAIT);

	ok(events == lttng::poller::event_type::NONE,
	   "Callback not called after event mask set to NONE");

	poller.modify(event_fd, lttng::poller::event_type::READABLE);
	events = lttng::poller::event_type::NONE;
	poller.poll(lttng::poller::timeout_type::NO_WAIT);

	ok(events == lttng::poller::event_type::READABLE,
	   "Callback called after event mask restored to READABLE");
}

void test_remove_fd()
{
	lttng::eventfd event_fd;
	lttng::poller poller;
	bool called = false;

	poller.add(event_fd,
		   lttng::poller::event_type::READABLE,
		   [&called](lttng::poller::event_type) { called = true; });
	poller.remove(event_fd);
	event_fd.increment();
	poller.poll(lttng::poller::timeout_type::NO_WAIT);

	ok(!called, "Callback not called after FD is removed");
}

void test_poll_timeout()
{
	lttng::poller poller;

	/* No FDs added, should return immediately. */
	poller.poll(lttng::poller::timeout_type::WAIT_FOREVER);
	ok(1, "Poll with an infinite timeout and no FDs returns immediately");
}

void test_poll_timerfd()
{
	lttng::poller poller;
	lttng::timerfd timer_fd;

	lttng::poller::event_type events = lttng::poller::event_type::NONE;
	bool fired = false;

	poller.add(timer_fd,
		   lttng::poller::event_type::READABLE,
		   [&events, &fired](lttng::poller::event_type e) {
			   events = e;
			   fired = true;
		   });

	const auto before_arming = std::chrono::steady_clock::now();
	timer_fd.settime(std::chrono::milliseconds(500));

	poller.poll(lttng::poller::timeout_type::WAIT_FOREVER);
	const auto return_time = std::chrono::steady_clock::now();

	const auto elapsed_time = return_time - before_arming;
	const auto elapsed_time_ms =
		std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time).count();
	ok(events == lttng::poller::event_type::READABLE,
	   "Timerfd triggered with a readable event");
	ok(elapsed_time_ms >= 500,
	   "%s",
	   fmt::format("Timerfd triggered after at least 500ms elapsed ({}ms)", elapsed_time_ms)
		   .c_str());

	events = lttng::poller::event_type::NONE;
	fired = false;
	poller.poll(lttng::poller::timeout_type::NO_WAIT);
	ok(events == lttng::poller::event_type::READABLE && fired == true,
	   "Timerfd re-triggers immediately if not reset");
	fmt::print("Timerfd re-triggers immediately if not reset: events={}, fired={}\n",
		   events,
		   fired);

	events = lttng::poller::event_type::NONE;
	fired = false;
	timer_fd.reset();
	poller.poll(lttng::poller::timeout_type::NO_WAIT);
	ok(events == lttng::poller::event_type::NONE && fired == false,
	   "Timerfd not triggered after poll (one shot behaviour expected)");

	events = lttng::poller::event_type::NONE;
	fired = false;
	timer_fd.settime(std::chrono::hours(24));
	poller.poll(lttng::poller::timeout_ms(500));
	ok(events == lttng::poller::event_type::NONE && fired == false,
	   "Timerfd not triggered after poll (24h timerfd set and 500ms timeout)");
}
} /* namespace */

int main([[maybe_unused]] int argc, [[maybe_unused]] char **argv)
{
	try {
		plan_tests(16);

		test_event_fd_increment_decrement();
		test_multiple_fds();
		test_modify_events();
		test_remove_fd();
		test_poll_timeout();
		test_poll_timerfd();
	} catch (const std::exception& e) {
		diag("Unhandled exception: %s", e.what());
		return 1;
	}

	return exit_status();
}