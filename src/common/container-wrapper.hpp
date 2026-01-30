/*
 * SPDX-FileCopyrightText: 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONTAINER_WRAPPER_H
#define LTTNG_CONTAINER_WRAPPER_H

#include <common/exception.hpp>
#include <common/format.hpp>
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
	template <typename IteratorContainerType, typename IteratorElementType>
	class _iterator : public std::iterator<std::random_access_iterator_tag, std::size_t> {
	public:
		explicit _iterator(IteratorContainerType& container, std::size_t start_index = 0) :
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

		ptrdiff_t operator-(const _iterator& other) const
		{
			return _index - other._index;
		}

		bool operator==(const _iterator& other) const noexcept
		{
			return _index == other._index;
		}

		bool operator!=(const _iterator& other) const noexcept
		{
			return !(*this == other);
		}

		bool operator<(const _iterator& other) const noexcept
		{
			return _index < other._index;
		}

		bool operator<=(const _iterator& other) const noexcept
		{
			return _index <= other._index;
		}

		bool operator>(const _iterator& other) const noexcept
		{
			return _index > other._index;
		}

		bool operator>=(const _iterator& other) const noexcept
		{
			return _index >= other._index;
		}

		typename std::conditional<std::is_pointer<IteratorElementType>::value,
					  IteratorElementType,
					  IteratorElementType&>::type
		operator*() const
		{
			return _container[_index];
		}

	private:
		IteratorContainerType& _container;
		std::size_t _index;
	};

	using iterator = _iterator<random_access_container_wrapper, ElementType>;
	using const_iterator = _iterator<const random_access_container_wrapper, const ElementType>;

public:
	explicit random_access_container_wrapper(ContainerType container) :
		_container{ std::move(container) }
	{
	}

	iterator begin() noexcept
	{
		return iterator(*this);
	}

	iterator end()
	{
		return iterator(*this, size());
	}

	const_iterator begin() const noexcept
	{
		return const_iterator(*this);
	}

	const_iterator end() const
	{
		return const_iterator(*this, size());
	}

	std::size_t size() const
	{
		return ContainerOperations::size(_container);
	}

	bool empty() const
	{
		return size() == 0;
	}

	typename std::conditional<std::is_pointer<ElementType>::value, ElementType, ElementType&>::type
	operator[](std::size_t index)
	{
		/*
		 * To share code between the const and mutable versions of this operator, 'this'
		 * is casted to a const reference. A const_cast then ensures that a mutable
		 * reference (or pointer) is returned.
		 *
		 * We typically avoid const_cast, but this is safe: if the user is calling the
		 * mutable version of this operator, it had a mutable object anyhow.
		 *
		 * For more information, see Item 3 of Effective C++.
		 */
		const auto& const_this = static_cast<const random_access_container_wrapper&>(*this);

		/* NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) */
		return const_cast<typename std::conditional<std::is_pointer<ElementType>::value,
							    ElementType,
							    ElementType&>::type>(const_this[index]);
	}

	typename std::conditional<std::is_pointer<ElementType>::value,
				  const ElementType,
				  const ElementType&>::type
	operator[](std::size_t index) const
	{
		if (index >= ContainerOperations::size(_container)) {
			throw std::invalid_argument(lttng::format(
				"Out of bound access through random_access_container_wrapper: index={}, size={}",
				index,
				size()));
		}

		return ContainerOperations::get(_container, index);
	}

protected:
	ContainerType _container;
};

/*
 * View adapter that allows a class to expose the dereferenced values of an internal
 * associative container (e.g., std::map<K, std::unique_ptr<V>>) through a range-based
 * interface. This enables users of the class to iterate over the contained objects
 * directly using range-based for loops without exposing the underlying storage details.
 *
 * Example:
 *   class session {
 *       using channels_view = lttng::utils::dereferenced_mapped_values_view<
 *           std::unordered_map<std::string, std::unique_ptr<channel>>, channel>;
 *
 *       channels_view channels() { return channels_view(_channels); }
 *   private:
 *       std::unordered_map<std::string, std::unique_ptr<channel>> _channels;
 *   };
 *
 *   // User code:
 *   for (auto& channel : session.channels()) { ... }
 */
template <typename ContainerType, typename ElementType>
class dereferenced_mapped_values_view {
public:
	using underlying_iterator = decltype(std::declval<ContainerType&>().begin());

	class iterator {
	public:
		using value_type = ElementType;
		using reference = ElementType&;
		using pointer = ElementType *;
		using difference_type = std::ptrdiff_t;
		using iterator_category = std::forward_iterator_tag;

		explicit iterator(underlying_iterator it) noexcept : _it(std::move(it))
		{
		}

		reference operator*() const noexcept
		{
			return *_it->second;
		}

		pointer operator->() const noexcept
		{
			return _it->second.get();
		}

		iterator& operator++() noexcept
		{
			++_it;
			return *this;
		}

		iterator operator++(int) noexcept
		{
			auto tmp = *this;
			++_it;
			return tmp;
		}

		bool operator==(const iterator& other) const noexcept
		{
			return _it == other._it;
		}

		bool operator!=(const iterator& other) const noexcept
		{
			return _it != other._it;
		}

	private:
		underlying_iterator _it;
	};

	explicit dereferenced_mapped_values_view(ContainerType& container) noexcept :
		_container(container)
	{
	}

	iterator begin() const noexcept
	{
		return iterator(_container.begin());
	}

	iterator end() const noexcept
	{
		return iterator(_container.end());
	}

private:
	ContainerType& _container;
};

} /* namespace utils */
} /* namespace lttng */

#endif /* LTTNG_CONTAINER_WRAPPER_H */
