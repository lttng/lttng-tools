/*
 * Copyright (C) 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef _LTTNG_BUG_H
#define _LTTNG_BUG_H

#define LTTNG_BUILD_RUNTIME_BUG_ON(EXPR)                                         \
	do {                                                                     \
		constexpr bool _lttng_bug_constexpr_result =                     \
			__builtin_constant_p(!!(EXPR)) ? !!(EXPR) : false;       \
		static_assert(!_lttng_bug_constexpr_result, "BUG_ON triggered"); \
		if (!_lttng_bug_constexpr_result) {                              \
			if (EXPR) {                                              \
				std::abort();                                    \
			}                                                        \
		}                                                                \
	} while (0)

#endif /* _LTTNG_BUG_H */
