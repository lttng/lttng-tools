/*
 * SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LTTNG_FS_UTILS_H
#define LTTNG_FS_UTILS_H

namespace lttng {
namespace utils {

bool fs_supports_madv_remove(const char *shm_path = nullptr);

} /* namespace utils */
} /* namespace lttng */

#endif /* LTTNG_FS_UTILS_H */
