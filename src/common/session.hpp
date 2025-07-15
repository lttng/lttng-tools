/*
 * SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
 * SPDX-License-Idenitfier: GPL-2.0-only
 */

#ifndef LTTNG_COMMON_SESSION_HPP
#define LTTNG_COMMON_SESSION_HPP

/*
 * Validate the session name for forbidden characters.
 *
 * Return 0 on success else -1 meaning a forbidden char. has been found.
 */
int session_validate_name(const char *name);

#endif /* LTTNG_COMMON_SESSION_HPP */