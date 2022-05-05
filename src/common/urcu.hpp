/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_URCU_H
#define LTTNG_URCU_H

#define _LGPL_SOURCE
#include <urcu.h>
#include <mutex>

namespace lttng {
namespace urcu {

namespace details {
/*
 * Wrapper around an urcu read lock which satisfies the 'Mutex' named
 * requirements of C++11. Satisfying those requirements facilitates the use of
 * standard concurrency support library facilities.
 *
 * read_lock is under the details namespace since it is unlikely to be used
 * directly by exception-safe code. See read_lock_guard.
 */
class read_lock {
public:
	read_lock() = default;

	/* "Not copyable" and "not moveable" Mutex requirements. */
	read_lock(read_lock const &) = delete;
	read_lock &operator=(read_lock const &) = delete;

	void lock()
	{
		rcu_read_lock();
	}

	bool try_lock()
	{
		lock();
		return true;
	}

	void unlock()
	{
		rcu_read_unlock();
	}
};
} /* namespace details */

/*
 * Provides the basic concept of std::lock_guard for rcu reader locks.
 *
 * The RCU reader lock is held for the duration of lock_guard's lifetime.
 */
class read_lock_guard {
public:
	read_lock_guard() : _guard(_lock)
	{
	}

	read_lock_guard(const read_lock_guard &) = delete;

private:
	details::read_lock _lock;
	std::lock_guard<details::read_lock> _guard;
};

} /* namespace urcu */
} /* namespace lttng */

#endif /* LTTNG_URCU_H */
