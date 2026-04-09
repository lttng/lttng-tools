/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_COMMAND_QUEUE_HPP
#define LTTNG_COMMAND_QUEUE_HPP

#include <common/eventfd.hpp>
#include <common/waiter.hpp>

#include <vendor/optional.hpp>

#include <deque>
#include <mutex>

namespace lttng {

/*
 * Base class that users should derive from when defining their command type.
 *
 * Provides optional synchronous completion support: command_queue's
 * send_and_wait() method uses the private waker to block the sender
 * until the consumer thread signals completion via _complete().
 *
 * Users who need a "result" from command processing should define
 * their own set_result()/get_result() methods on their derived type.
 */
class command_base {
public:
	command_base() = default;
	virtual ~command_base() = default;

	command_base(command_base&& other) noexcept = default;
	command_base& operator=(command_base&& other) noexcept = default;
	command_base(const command_base&) = delete;
	command_base& operator=(const command_base&) = delete;

	/*
	 * Signal completion of this command. If a sender is blocked in
	 * send_and_wait(), this wakes it up. Safe to call even if no
	 * waker was set (fire-and-forget commands).
	 *
	 * Must be called by the consumer thread after processing the command.
	 */
	void _complete() noexcept
	{
		if (_completed_waker) {
			_completed_waker->wake();
		}
	}

private:
	template <typename>
	friend class command_queue;

	void _set_waker(lttng::synchro::waker waker) noexcept
	{
		_completed_waker = waker;
	}

	nonstd::optional<lttng::synchro::waker> _completed_waker;
};

/*
 * Thread-safe command queue with eventfd-based wakeup.
 *
 * CommandType should derive from command_base and define move semantics
 * if copies are costly. The queue accepts commands by value (callers
 * can std::move into it).
 *
 * send()          : fire-and-forget: enqueue + wake eventfd.
 * send_and_wait() : enqueue + wake + block until the consumer thread
 *                   calls _complete() on the command.
 *
 * The waiter/waker plumbing is entirely internal; callers never touch it.
 */
template <typename CommandType>
class command_queue {
public:
	/*
	 * Non-semaphore semantics: decrement() returns the accumulated
	 * counter and resets it to zero, which is what drain() needs.
	 */
	command_queue() : _wake_fd(false)
	{
	}
	~command_queue() = default;

	command_queue(const command_queue&) = delete;
	command_queue(command_queue&&) = delete;
	command_queue& operator=(const command_queue&) = delete;
	command_queue& operator=(command_queue&&) = delete;

	void send(CommandType cmd)
	{
		const std::lock_guard<std::mutex> guard(_lock);

		_queue.emplace_back(std::move(cmd));
		_wake_fd.increment();
	}

	void send_and_wait(CommandType cmd)
	{
		lttng::synchro::waiter completion_waiter;

		cmd._set_waker(completion_waiter.get_waker());

		{
			const std::lock_guard<std::mutex> guard(_lock);

			_queue.emplace_back(std::move(cmd));
			_wake_fd.increment();
		}

		completion_waiter.wait();
	}

	nonstd::optional<CommandType> pop()
	{
		const std::lock_guard<std::mutex> guard(_lock);

		if (_queue.empty()) {
			_wake_fd.decrement();
			return nonstd::nullopt;
		}

		auto cmd = nonstd::optional<CommandType>(std::move(_queue.front()));
		_queue.pop_front();
		return cmd;
	}

	/*
	 * Non-blocking pop: returns the front element if one is queued,
	 * nullopt otherwise. Unlike pop(), never touches the eventfd so
	 * it is safe to call even when no wakeup event is pending.
	 */
	nonstd::optional<CommandType> try_pop()
	{
		const std::lock_guard<std::mutex> guard(_lock);

		if (_queue.empty()) {
			return nonstd::nullopt;
		}

		auto cmd = nonstd::optional<CommandType>(std::move(_queue.front()));
		_queue.pop_front();
		return cmd;
	}

	const lttng::eventfd& wake_fd() const noexcept
	{
		return _wake_fd;
	}

private:
	lttng::eventfd _wake_fd;
	std::mutex _lock;
	std::deque<CommandType> _queue;
};

} /* namespace lttng */

#endif /* LTTNG_COMMAND_QUEUE_HPP */
