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
	using referenced_type = ReferencedType;
	using deleter = CustomDeleter;

	non_copyable_reference(non_copyable_reference&& other) noexcept : _value(other._value)
	{
		_value = other._value;
		other.release();
	}

	non_copyable_reference() = delete;
	non_copyable_reference(const non_copyable_reference&) = delete;
	non_copyable_reference& operator=(non_copyable_reference&& other) noexcept
	{
		if (this != &other) {
			_clean_up();
			_value = other._value;
			other.release();
		}

		return *this;
	}

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

	void release() noexcept
	{
		_value = nullptr;
	}

	~non_copyable_reference()
	{
		_clean_up();
	}

private:
	explicit non_copyable_reference(ReferencedType& instance) noexcept : _value(&instance)
	{
	}

	void _clean_up()
	{
		if (!_value) {
			return;
		}

		typename CustomDeleter::deleter del;
		del(_value);
		release();
	}

	template <typename FactoryReferencedType, typename FactoryCustomDeleter>
	friend non_copyable_reference<FactoryReferencedType, FactoryCustomDeleter>
	make_non_copyable_reference(FactoryReferencedType&);

	ReferencedType *_value = nullptr;
};

template <typename ReferencedType, typename CustomDeleter>
non_copyable_reference<ReferencedType, CustomDeleter>
make_non_copyable_reference(ReferencedType& instance)
{
	return non_copyable_reference<ReferencedType, CustomDeleter>(instance);
}

} /* namespace lttng */

#endif /* LTTNG_REFERENCE_H */
