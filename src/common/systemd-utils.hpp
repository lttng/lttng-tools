/*
 * SPDX-FileCopyrightText: 2025 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#ifndef LTTNG_COMMON_SYSTEMD_UTILS_HPP
#define LTTNG_COMMON_SYSTEMD_UTILS_HPP

namespace lttng {
namespace systemd {

void notify_ready();
void notify_stopping();

} /* namespace systemd */
} /* namespace lttng */

#endif /* LTTNG_COMMON_SYSTEMD_UTILS_HPP */
