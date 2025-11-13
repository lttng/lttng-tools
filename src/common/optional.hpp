/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_OPTIONAL_H
#define LTTNG_OPTIONAL_H

#include <common/macros.hpp>

#include <stdint.h>
#include <utility>

/*
 * Define wrapper structure representing an optional value.
 *
 * This macro defines an "is_set" boolean field that must be checked
 * when accessing the optional field. This "is_set" field provides
 * the semantics that would be expected of a typical "raw pointer" field
 * which would be checked for NULL.
 *
 * Prefer using this macro where "special" values would be used, e.g.
 * -1ULL for uint64_t types.
 *
 * Declaration example:
 * struct my_struct {
 * 	int a;
 * 	LTTNG_OPTIONAL(int) b;
 * };
 *
 * Usage example:
 * struct my_struct foo = LTTNG_OPTIONAL_INIT;
 *
 * LTTNG_OPTIONAL_SET(&foo.b, 42);
 * if (foo.b.is_set) {
 * 	printf("%d", foo.b.value);
 * }
 *
 * LTTNG_OPTIONAL_UNSET(&foo.b);
 */
#define LTTNG_OPTIONAL(type)    \
	struct {                \
		uint8_t is_set; \
		type value;     \
	}

/*
 * Alias used for communication structures. If the layout of an LTTNG_OPTIONAL
 * is changed, the original layout should still be used for communication
 * purposes.
 *
 * LTTNG_OPTIONAL_COMM should be combined with the LTTNG_PACKED macro when
 * used for IPC / network communication.
 */
#define LTTNG_OPTIONAL_COMM LTTNG_OPTIONAL

/*
 * This macro is available as a 'convenience' to allow sites that assume
 * an optional value is set to LTTNG_ASSERT() that it is set when accessing it.
 *
 * Since this returns the 'optional' by value, it is not suitable for all
 * wrapped optional types. It is meant to be used with PODs.
 */
#define LTTNG_OPTIONAL_GET(optional)                                                  \
	({                                                                            \
		DIAGNOSTIC_PUSH                                                       \
		DIAGNOSTIC_IGNORE_ADDRESS_OF_PACKED_MEMBER                            \
		auto _result = ::details::lttng_optional_get_value_impl(&(optional)); \
		DIAGNOSTIC_POP                                                        \
		_result;                                                              \
	})

/*
 * This macro is available as a 'convenience' to allow sites that assume
 * an optional value is set to LTTNG_ASSERT() that it is set when fecthing the
 * underlying value's address.
 */
#define LTTNG_OPTIONAL_GET_PTR(optional) ::details::lttng_optional_get_value_ptr_impl(optional)

/*
 * Initialize an optional field as unset.
 *
 * The wrapped field is set to the value it would gave if it had static storage
 * duration.
 */
#define LTTNG_OPTIONAL_INIT_UNSET \
	{                         \
	}

/*
 * Initialize an optional field as 'set' with a given value.
 */
#define LTTNG_OPTIONAL_INIT_VALUE(val)      \
	{                                   \
		.is_set = 1, .value = (val) \
	}

/* Set the value of an optional field. */
#define LTTNG_OPTIONAL_SET(field_ptr, val)                                                    \
	do {                                                                                  \
		DIAGNOSTIC_PUSH                                                               \
		DIAGNOSTIC_IGNORE_ADDRESS_OF_PACKED_MEMBER                                    \
		static_assert(                                                                \
			std::is_same<typename std::decay<decltype((field_ptr)->value)>::type, \
				     typename std::decay<decltype(val)>::type>::value,        \
			"Type mismatch between optional field and value");                    \
		::details::lttng_optional_set_impl(field_ptr, val);                           \
		DIAGNOSTIC_POP                                                                \
	} while (0)

/* Put an optional field in the "unset" (NULL-ed) state. */
#define LTTNG_OPTIONAL_UNSET(field_ptr)                                            \
	do {                                                                       \
		DIAGNOSTIC_PUSH                                                    \
		DIAGNOSTIC_IGNORE_ADDRESS_OF_PACKED_MEMBER                         \
		std::memset(&(field_ptr)->is_set, 0, sizeof((field_ptr)->is_set)); \
		DIAGNOSTIC_POP                                                     \
	} while (0)

namespace details {
template <typename OptionalType, typename ValueType>
inline void lttng_optional_set_impl(OptionalType *field_ptr, const ValueType& val)
{
	/*
	 * Verify that is_set is at offset 0, so we can safely access it via
	 * char pointer cast without computing member offsets.
	 */
	static_assert(offsetof(OptionalType, is_set) == 0,
		      "is_set must be at offset 0 in the optional struct");

	/*
	 * Use memset and memcpy to avoid potential issues with
	 * assignment to packed structures / unaligned access.
	 *
	 * Use char pointer to avoid alignment checks when accessing packed structs.
	 */
	auto *const is_set_ptr = reinterpret_cast<char *>(field_ptr);
	memset(is_set_ptr, 1, sizeof(field_ptr->is_set));

	/*
	 * Use offsetof and sizeof on the value type to avoid any member access
	 * that could trigger alignment checks on packed structs.
	 */
	using DecayedValueType = typename std::decay<ValueType>::type;
	constexpr auto value_offset = offsetof(OptionalType, value);
	auto *const value_ptr = reinterpret_cast<char *>(field_ptr) + value_offset;
	memcpy(value_ptr, &val, sizeof(DecayedValueType));
}

/* Overload for r-value. */
template <typename OptionalType, typename ValueType>
inline void lttng_optional_set_impl(OptionalType *field_ptr, const ValueType&& val)
{
	/*
	 * Use std::decay on the template parameter type to strip any
	 * cv-qualifiers and references, ensuring tmp_value has proper alignment.
	 */
	using DecayedValueType = typename std::decay<ValueType>::type;
	const DecayedValueType tmp_value = std::move(val);

	/*
	 * Verify that is_set is at offset 0, so we can safely access it via
	 * char pointer cast without computing member offsets.
	 */
	static_assert(offsetof(OptionalType, is_set) == 0,
		      "is_set must be at offset 0 in the optional struct");

	/* Use char pointer to avoid alignment checks when accessing packed structs. */
	auto *const is_set_ptr = reinterpret_cast<char *>(field_ptr);
	memset(is_set_ptr, 1, sizeof(field_ptr->is_set));

	/*
	 * Use offsetof and sizeof on the decayed type to avoid any member access
	 * that could trigger alignment checks on packed structs.
	 */
	constexpr auto value_offset = offsetof(OptionalType, value);
	auto *const value_ptr = reinterpret_cast<char *>(field_ptr) + value_offset;
	memcpy(value_ptr, &tmp_value, sizeof(DecayedValueType));
}

template <typename OptionalType,
	  typename ValueType =
		  typename std::decay<decltype(std::declval<OptionalType>().value)>::type>
inline ValueType lttng_optional_get_value_impl(const OptionalType *field_ptr)
{
	/*
	 * Use memcpy to avoid alignment issues when accessing members
	 * of packed structs. This prevents undefined behavior when fields
	 * are misaligned. We must avoid any direct member access including
	 * the is_set field.
	 */
	uint8_t is_set;
	auto *const is_set_ptr = reinterpret_cast<const char *>(field_ptr);
	memcpy(&is_set, is_set_ptr, sizeof(uint8_t));
	LTTNG_ASSERT(is_set);

	ValueType result;
	constexpr auto value_offset = offsetof(OptionalType, value);
	auto *const value_ptr = reinterpret_cast<const char *>(field_ptr) + value_offset;
	memcpy(&result, value_ptr, sizeof(ValueType));
	return result;
}

template <typename OptionalType,
	  typename ValueType = typename std::decay<decltype(OptionalType::value)>::type>
inline ValueType *lttng_optional_get_value_ptr_impl(OptionalType& field_ptr)
{
	LTTNG_ASSERT(field_ptr.is_set);
	return &field_ptr.value;
}

template <typename OptionalType,
	  typename ValueType = typename std::decay<decltype(OptionalType::value)>::type>
inline const ValueType *lttng_optional_get_value_ptr_impl(const OptionalType& field_ptr)
{
	LTTNG_ASSERT(field_ptr.is_set);
	return &field_ptr.value;
}

} /* namespace details */

#endif /* LTTNG_OPTIONAL_H */
