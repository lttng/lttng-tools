/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONTAINER_WRAPPER_H
#define LTTNG_CONTAINER_WRAPPER_H

#include <common/macros.hpp>

#include <cstddef>
#include <iterator>

namespace lttng {
namespace utils {

/*
 * random_access_container_wrapper is a helper to provide an idiomatic C++ interface
 * from a C container API. ElementAccessorCallable and ElementCountAccessorCallable
 * are two functors which must be provided to allow access to the underlying elements
 * of the container and to its size.
 */
template <typename ContainerType, typename ElementType, typename ContainerOperations>
class random_access_container_wrapper {
	class _iterator : public std::iterator<std::random_access_iterator_tag, std::size_t> {
	public:
		explicit _iterator(const random_access_container_wrapper& container,
				   std::size_t start_index = 0) :
			_container(container), _index(start_index)
		{
		}

		_iterator& operator++() noexcept
		{
			++_index;
			return *this;
		}

		_iterator& operator--() noexcept
		{
			--_index;
			return *this;
		}

		_iterator& operator++(int) noexcept
		{
			auto this_before_increment = *this;

			_index++;
			return this_before_increment;
		}

		_iterator& operator--(int) noexcept
		{
			_index--;
			return *this;
		}

		bool operator==(const _iterator& other) const noexcept
		{
			return _index == other._index;
		}

		bool operator!=(const _iterator& other) const noexcept
		{
			return !(*this == other);
		}

		typename std::conditional<std::is_pointer<ElementType>::value,
					  ElementType,
					  ElementType&>::type
		operator*() const noexcept
		{
			return _container[_index];
		}

	private:
		const random_access_container_wrapper& _container;
		std::size_t _index;
	};

	using iterator = _iterator;

public:
	explicit random_access_container_wrapper(ContainerType container) : _container{ container }
	{
	}

	iterator begin() noexcept
	{
		return iterator(*this);
	}

	iterator end() noexcept
	{
		return iterator(*this, ContainerOperations::size(_container));
	}

	std::size_t size() const noexcept
	{
		return ContainerOperations::size(_container);
	}

	typename std::conditional<std::is_pointer<ElementType>::value, ElementType, ElementType&>::type
	operator[](std::size_t index)
	{
		LTTNG_ASSERT(index < ContainerOperations::size(_container));
		return ContainerOperations::get(_container, index);
	}

	typename std::conditional<std::is_pointer<ElementType>::value,
				  const ElementType,
				  const ElementType&>::type
	operator[](std::size_t index) const
	{
		LTTNG_ASSERT(index < ContainerOperations::size(_container));
		return ContainerOperations::get(_container, index);
	}

private:
	ContainerType _container;
};
} /* namespace utils */
} /* namespace lttng */

#endif /* LTTNG_CONTAINER_WRAPPER_H */
