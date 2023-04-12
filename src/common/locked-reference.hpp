/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOCKED_REFERENCE_H
#define LTTNG_LOCKED_REFERENCE_H

#define _LGPL_SOURCE
#include <mutex>

namespace lttng {

/*
 * A locked reference is useful to return a reference to an object
 * while ensuring that the caller uses it within a given locking context.
 *
 * For instance, a number of look-up APIs return an object and require the
 * caller to hold the RCU reader lock for the duration of their use of the
 * return value.
 *
 * Using a locked_reference, a function returning such an object can:
 *   - acquire the rcu read lock using a unique_read_lock,
 *   - perform its look-up
 *   - return a reference to which the unique_read_lock is transferred.
 *
 * Note that this locked reference can be used like a pointer
 * (see operators `*` and `->`). However, note that it is a _reference_.
 * Hence, _it can't be null_.
 *
 * Functions returning this type will most likely throw an exception
 * when the look-up fails.
 */
template <class WrappedType, class UniqueLockType>
class locked_reference {
public:
	locked_reference(WrappedType& value, UniqueLockType&& lock) :
		_value(value), _lock(std::move(lock))
	{
	}

	WrappedType& operator*() const
	{
		return _value;
	}

	WrappedType *operator->() const
	{
		return &_value;
	}

private:
	WrappedType& _value;
	UniqueLockType _lock;
};

} /* namespace lttng */

#endif /* LTTNG_LOCKED_REFERENCE_H */
