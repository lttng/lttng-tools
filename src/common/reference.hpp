/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_REFERENCE_H
#define LTTNG_REFERENCE_H

#include <algorithm>
#include <utility>

namespace lttng {

template <typename ReferencedType, typename CustomDeleter>
class non_copyable_reference {
public:
	explicit non_copyable_reference(ReferencedType& instance) noexcept : _value(&instance)
	{
	}

	non_copyable_reference(non_copyable_reference&& other) noexcept : _value(other._value)
	{
		other._value = nullptr;
	}

	non_copyable_reference() = delete;
	non_copyable_reference(const non_copyable_reference&) = delete;
	non_copyable_reference& operator=(non_copyable_reference&&) = delete;
	non_copyable_reference& operator=(const non_copyable_reference&) = delete;

	ReferencedType& get() const noexcept
	{
		return *_value;
	}

	ReferencedType *operator->() const noexcept
	{
		return _value;
	}

	ReferencedType& operator*() const noexcept
	{
		return *_value;
	}

	~non_copyable_reference()
	{
		if (!_value) {
			return;
		}

		typename CustomDeleter::deleter del;
		del(_value);
	}

private:
	ReferencedType *_value = nullptr;
};

} /* namespace lttng */

#endif /* LTTNG_REFERENCE_H */
