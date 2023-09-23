/*
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * This code is originally adapted from userspace-rcu's urcu-wait.h
 */

#ifndef LTTNG_WAITER_H
#define LTTNG_WAITER_H

#define _LGPL_SOURCE

#include "macros.hpp"

#include <stdbool.h>
#include <stdint.h>
#include <urcu/wfstack.h>

namespace lttng {
namespace synchro {
class waiter;
class wait_queue;

class waker {
	friend waiter;

public:
	waker(const waker&) = default;
	waker(waker&&) = default;
	waker& operator=(const waker& other)
	{
		_state = other._state;
		return *this;
	}
	waker& operator=(waker&& other)
	{
		_state = other._state;
		return *this;
	}

	void wake();

	~waker() = default;

private:
	waker(int32_t& state) : _state{ state }
	{
	}

	int32_t& _state;
};

class waiter final {
	friend wait_queue;

public:
	waiter();

	/* Deactivate copy and assignment. */
	waiter(const waiter&) = delete;
	waiter(waiter&&) = delete;
	waiter& operator=(const waiter&) = delete;
	waiter& operator=(waiter&&) = delete;
	~waiter() = default;

	void arm() noexcept;
	void wait();

	waker get_waker();

private:
	cds_wfs_node _wait_queue_node;
	int32_t _state;
};

class wait_queue final {
public:
	wait_queue();

	/* Deactivate copy and assignment. */
	wait_queue(const wait_queue&) = delete;
	wait_queue(wait_queue&&) = delete;
	wait_queue& operator=(const wait_queue&) = delete;
	wait_queue& operator=(wait_queue&&) = delete;
	~wait_queue() = default;

	/*
	 * Atomically add a waiter to a wait queue.
	 * A full memory barrier is issued before being added to the wait queue.
	 */
	void add(waiter& waiter) noexcept;
	/*
	 * Wake every waiter present in the wait queue and remove them from
	 * the queue.
	 */
	void wake_all();

private:
	cds_wfs_stack _stack;
};
} /* namespace synchro */
} /* namespace lttng */

#endif /* LTTNG_WAITER_H */
