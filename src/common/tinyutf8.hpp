/*
 * SPDX-FileCopyrightText: 2025 Philippe Proulx <eeppeliteloop@gmail.com>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_COMMON_TINYUTF8_HPP
#define LTTNG_COMMON_TINYUTF8_HPP

#include <common/macros.hpp>

/*
 * Wrapper around the vendored tiny-utf8 header which silences the
 * warnings it triggers under this project's diagnostic flags.
 *
 * Always include this header instead of <vendor/tinyutf8.h> directly so
 * that the suppression is applied consistently.
 */
DIAGNOSTIC_PUSH
DIAGNOSTIC_IGNORE_SHADOW
#include <vendor/tinyutf8.h>
DIAGNOSTIC_POP

#endif /* LTTNG_COMMON_TINYUTF8_HPP */
