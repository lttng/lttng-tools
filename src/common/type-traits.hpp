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
 * `true` if `T` is in the list of types `Ts`.
 */
template <typename T, typename... Ts>
inline constexpr bool is_one_of = (std::is_same_v<T, Ts> || ...);
} /* namespace traits */
} /* namespace lttng */

#endif /* LTTNG_TYPE_TRAITS_HPP */
