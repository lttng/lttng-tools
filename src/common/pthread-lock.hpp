/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_PTHREAD_LOCK_H
#define LTTNG_PTHREAD_LOCK_H

#include <common/exception.hpp>

#include <mutex>
#include <pthread.h>

namespace lttng {
namespace pthread {

namespace details {
/*
 * Class wrapping pthread mutexes and satisfying the Mutex named requirements, except
 * for the "Default Constructible" requirement. The class is not default-constructible since the
 * intention is to ease the transition of existing C-code using pthread mutexes to idiomatic C++.
 *
 * New code should use std::mutex.
 */
class mutex {
public:
	explicit mutex(pthread_mutex_t& mutex_p) : _mutex(mutex_p)
	{
	}

	~mutex() = default;

	/* "Not copyable" and "not moveable" Mutex requirements. */
	mutex(mutex const&) = delete;
	mutex(mutex&&) = delete;
	mutex& operator=(mutex const&) = delete;
	mutex& operator=(mutex&&) = delete;

	void lock()
	{
		if (pthread_mutex_lock(&_mutex) != 0) {
			LTTNG_THROW_POSIX("Failed to lock mutex", errno);
		}
	}

	bool try_lock()
	{
		const auto ret = pthread_mutex_trylock(&_mutex);

		if (ret == 0) {
			return true;
		} else if (errno == EBUSY || errno == EAGAIN) {
			return false;
		} else {
			LTTNG_THROW_POSIX("Failed to try to lock mutex", errno);
		}
	}

	void unlock()
	{
		if (pthread_mutex_unlock(&_mutex) != 0) {
			/*
			 * Unlock cannot throw as it is called as part of lock_guard's destructor.
			 */
			abort();
		}
	}

private:
	pthread_mutex_t& _mutex;
};
} /* namespace details */

/*
 * Provides the basic concept of std::lock_guard for posix mutexes.
 *
 * `lock` is held for the duration of lock_guard's lifetime.
 */
class lock_guard {
public:
	explicit lock_guard(pthread_mutex_t& mutex) : _mutex(mutex), _guard(_mutex)
	{
	}

	~lock_guard() = default;

	lock_guard(const lock_guard&) = delete;
	lock_guard(lock_guard&&) = delete;
	lock_guard& operator=(const lock_guard&) = delete;
	lock_guard& operator=(lock_guard&&) = delete;

private:
	details::mutex _mutex;
	std::lock_guard<details::mutex> _guard;
};

} /* namespace pthread */
} /* namespace lttng */

#endif /* LTTNG_PTHREAD_LOCK_H */
