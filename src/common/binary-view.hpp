/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_BINARY_VIEW_HPP
#define LTTNG_BINARY_VIEW_HPP

#include <common/exception.hpp>

#include <type_traits>

namespace lttng {

/*
 * binary_view provides a type-safe, non-owning view over a contiguous region of memory interpreted
 * as an array of Valuetype elements. This utility is intended for safely handling binary protocols
 * and memory-mapped structures, allowing iteration and indexed access to elements without copying
 * or ownership semantics.
 *
 * The binary_view performs bounds checking on construction and element access, throwing exceptions
 * on invalid usage. It is especially useful for decoding protocol messages or file formats where
 * the layout is known at compile time.
 *
 * Example usage:
 *
 * struct my_struct {
 *     uint32_t id;
 *     uint64_t timestamp;
 * };
 *
 * // Assume `buffer` is a pointer to a binary buffer received from a protocol,
 * // and `buffer_size` is its size in bytes.
 * const void *buffer = ...;
 * size_t buffer_size = ...;
 *
 * // Create a view over the buffer as an array of my_struct.
 * lttng::binary_view<my_struct> view(buffer, buffer_size, expected_element_count);
 *
 * // Iterate over the elements safely.
 * for (const auto& elem : view) {
 *     fmt::format("id: {}, timestamp: {}", elem.id, elem.timestamp);
 * }
 *
 * // Access an element by index with bounds checking.
 * const auto& first = view[0];
 */
template <typename ValueType>
class binary_view final {
public:
	using value_type = ValueType;
	using pointer = const ValueType *;
	using reference = const ValueType&;
	using const_iterator = pointer;
	using size_type = std::size_t;

	binary_view(const void *data, size_type size_bytes, size_type count = 1) :
		_data(reinterpret_cast<pointer>(data)), _count(count)
	{
		static_assert(std::is_trivially_copyable<ValueType>::value,
			      "ValueType must be trivially copyable");

		if (!_data) {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(
				"Null data pointer provided to binary_view");
		}

		if (size_bytes < count * sizeof(ValueType)) {
			LTTNG_THROW_OUT_OF_RANGE(fmt::format(
				"Buffer size is too small for expected elements: size={}, element_count={}, element_size={}",
				size_bytes,
				count,
				sizeof(ValueType)));
		}
	}

	/* Note that begin() returns a potentially unaligned pointer. */
	const_iterator begin() const noexcept
	{
		return reinterpret_cast<const ValueType *>(_data);
	}

	const_iterator end() const noexcept
	{
		return begin() + _count;
	}

	value_type operator[](size_type idx) const
	{
		if (idx >= _count) {
			LTTNG_THROW_OUT_OF_RANGE(fmt::format(
				"Binary view index out of range: index={}, count={}", idx, _count));
		}

		return value(idx);
	}

	size_type size() const noexcept
	{
		return _count;
	}

	bool empty() const noexcept
	{
		return _count == 0;
	}

	value_type value(size_type idx = 0) const
	{
		if (idx >= _count) {
			LTTNG_THROW_OUT_OF_RANGE(fmt::format(
				"Binary view index out of range: index={}, count={}", idx, _count));
		}

#if (defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)) || \
	(defined(__i486__) || defined(__i586__) || defined(__i686__)) ||                    \
	(defined(__i386__) || defined(__i386)) ||                                           \
	(defined(__powerpc64__) || defined(__ppc64__)) ||                                   \
	(defined(__powerpc__) || defined(__powerpc) || defined(__ppc__))
		/* x86/x64 and ppc/ppc64 allow unaligned access; just dereference. */
		return begin()[idx];
#else
		/* Other architectures, use memcpy for safety. */
		value_type result;

		std::memcpy(&result, _data + idx, sizeof(ValueType));
		return result;
#endif
	}

private:
	const pointer _data;
	const size_type _count;
};
} /* namespace lttng */

#endif /* LTTNG_BINARY_VIEW_HPP */
