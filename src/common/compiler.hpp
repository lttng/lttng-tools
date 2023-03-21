/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMPILER_HPP
#define LTTNG_COMPILER_HPP

/*
 * A bug in gcc [6.1, 7.4] causes flexible array members to generate a destructor
 * for compound types. In turn, this makes any type that contains a flexible array
 * a non-POD object which is a problem under some use-case (e.g., being allocated
 * using C-style memory management facilities).
 *
 * Explicitly specifying a length of zero works around this bug, see:
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=70932
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=71147
 */
#if !defined(__clang__) && defined(__GNUC__) && \
	((__GNUC__ == 6 && __GNUC_MINOR__ >= 1) || ((__GNUC__ == 7 && __GNUC_MINOR__ <= 4)))
#define LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH 0
#else
#define LTTNG_FLEXIBLE_ARRAY_MEMBER_LENGTH
#endif /* gcc version [6.1, 7.4]. */

#endif /* LTTNG_COMPILER_HPP */
