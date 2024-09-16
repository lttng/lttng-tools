/*
 * Copyright (c) 2023 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef LTTNG_TYPE_TRAITS_HPP
#define LTTNG_TYPE_TRAITS_HPP

#include <type_traits>

namespace lttng {
namespace traits {

/*
 * Provides the member constant `value` equal to:
 *
 * `T` is in the list of types `Ts`:
 *     `true`
 *
 * Otherwise:
 *     `false`
 */
template <typename T, typename... Ts>
struct is_one_of : std::false_type {};

template <typename T, typename... Ts>
struct is_one_of<T, T, Ts...> : std::true_type {};

template <typename T, typename U, typename... Ts>
struct is_one_of<T, U, Ts...> : is_one_of<T, Ts...> {};
} /* namespace traits */
} /* namespace lttng */

#endif /* LTTNG_TYPE_TRAITS_HPP */
